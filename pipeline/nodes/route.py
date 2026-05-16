from __future__ import annotations
"""
Node 5: Triage Routing
Maps analysis + confidence → final decision:
  CRITICAL  → auto-escalate + human review
  HIGH      → human review queue
  MEDIUM    → monitor / SOC tier-1
  LOW       → log and close
  BENIGN    → dismiss
"""
import config
from pipeline.state import AlertState


# Reason codes
RC_CRITICAL_TECHNIQUE   = "CRITICAL_TECHNIQUE_DETECTED"
RC_HIGH_CONFIDENCE      = "HIGH_CONFIDENCE_THREAT"
RC_RANSOMWARE_INDICATOR = "RANSOMWARE_INDICATOR"
RC_LATERAL_MOVEMENT     = "LATERAL_MOVEMENT_DETECTED"
RC_CREDENTIAL_THEFT     = "CREDENTIAL_THEFT_INDICATOR"
RC_C2_COMMUNICATION     = "C2_COMMUNICATION_DETECTED"
RC_EXPLOIT_ATTEMPT      = "EXPLOIT_ATTEMPT"
RC_LOW_CONFIDENCE       = "LOW_CONFIDENCE_ESCALATE"
RC_MEDIUM_MONITOR       = "MEDIUM_SEVERITY_MONITOR"
RC_LOW_LOG              = "LOW_SEVERITY_LOG"
RC_BENIGN_DISMISS       = "BENIGN_FALSE_POSITIVE"
RC_UNKNOWN_ESCALATE     = "UNKNOWN_SEVERITY_ESCALATE"

# MITRE techniques that warrant CRITICAL regardless of LLM severity call
_CRITICAL_TECHNIQUES = {
    "T1486",           # Data Encrypted for Impact (ransomware)
    "T1490",           # Inhibit System Recovery
    "T1485",           # Data Destruction
    "T1561",           # Disk Wipe
}
_HIGH_TECHNIQUES = {
    "T1055",           # Process Injection
    "T1003",           # OS Credential Dumping
    "T1078",           # Valid Accounts (privilege escalation)
    "T1021",           # Remote Services (lateral movement)
    "T1071",           # Application Layer Protocol (C2)
    "T1190",           # Exploit Public-Facing Application
}


def _technique_override(tech_ids: list[str]) -> tuple[str, list[str]]:
    """
    Check if any extracted technique IDs force a severity override.
    Returns (override_severity_or_None, reason_codes).
    """
    ids_upper = {t.split(".")[0].upper() for t in tech_ids}
    reasons = []

    if ids_upper & {t.upper() for t in _CRITICAL_TECHNIQUES}:
        reasons.append(RC_CRITICAL_TECHNIQUE)
        if "T1486" in ids_upper or "T1486" in tech_ids:
            reasons.append(RC_RANSOMWARE_INDICATOR)
        return "CRITICAL", reasons

    if ids_upper & {t.upper() for t in _HIGH_TECHNIQUES}:
        if "T1021" in ids_upper:
            reasons.append(RC_LATERAL_MOVEMENT)
        if "T1003" in ids_upper:
            reasons.append(RC_CREDENTIAL_THEFT)
        if "T1071" in ids_upper:
            reasons.append(RC_C2_COMMUNICATION)
        if "T1190" in ids_upper:
            reasons.append(RC_EXPLOIT_ATTEMPT)
        return "HIGH", reasons

    return "", []


def route_node(state: AlertState) -> dict:
    """
    Routing node.
    Input:  analysis, confidence_score, confidence_band
    Output: triage_decision, reason_codes, human_review_required (may upgrade)
    """
    if state.get("error"):
        return {}

    analysis   = state.get("analysis", {})
    band       = state.get("confidence_band", "LOW")
    score      = state.get("confidence_score", 0.3)
    tech_ids   = analysis.get("technique_ids") or []
    llm_sev    = (analysis.get("severity") or "UNKNOWN").upper()

    reasons: list[str] = []

    # ── Technique-level hard overrides ───────────────────────────────────
    override_sev, override_reasons = _technique_override(tech_ids)
    if override_sev:
        severity = override_sev
        reasons.extend(override_reasons)
    else:
        severity = llm_sev

    # ── Map severity → decision ──────────────────────────────────────────
    if severity == "CRITICAL":
        decision = "CRITICAL"
        reasons.append(RC_CRITICAL_TECHNIQUE if RC_CRITICAL_TECHNIQUE not in reasons
                       else RC_HIGH_CONFIDENCE)
    elif severity == "HIGH":
        decision = "HIGH"
        if not reasons:
            reasons.append(RC_HIGH_CONFIDENCE)
    elif severity == "MEDIUM":
        decision = "MEDIUM"
        reasons.append(RC_MEDIUM_MONITOR)
    elif severity == "LOW":
        decision = "LOW"
        reasons.append(RC_LOW_LOG)
    elif severity == "BENIGN":
        decision = "BENIGN"
        reasons.append(RC_BENIGN_DISMISS)
    else:
        # UNKNOWN — escalate for safety
        decision = "HIGH"
        reasons.append(RC_UNKNOWN_ESCALATE)

    # ── LOW confidence always escalates to at least MEDIUM ───────────────
    if band == "LOW" and config.SEVERITY_RANK.get(decision, 0) < config.SEVERITY_RANK["MEDIUM"]:
        decision = "MEDIUM"
        reasons.append(RC_LOW_CONFIDENCE)

    # ── Human review ─────────────────────────────────────────────────────
    human_review = decision in config.HUMAN_REVIEW_SEVERITIES or band == "LOW"

    return {
        "triage_decision":       decision,
        "reason_codes":          list(dict.fromkeys(reasons)),  # deduplicate, preserve order
        "human_review_required": human_review,
    }
