from __future__ import annotations
"""
Node 1: Alert Intake
- Normalises raw alert text (Syslog / EDR JSON / plain text)
- Detects alert source type
- Extracts key metadata (timestamp, host, process, user, IP)
- Assigns a unique ALERT-ID
"""
import json
import re
import uuid
from datetime import datetime

import config
from pipeline.state import AlertState


# ── Regex patterns for common alert fields ────────────────────────────────────
_RE_IP      = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
_RE_HASH    = re.compile(r'\b[0-9a-fA-F]{32,64}\b')
_RE_CVE     = re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE)
_RE_MITRE   = re.compile(r'T\d{4}(?:\.\d{3})?', re.IGNORECASE)
_RE_TS_ISO  = re.compile(r'\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}')
_RE_SYSLOG  = re.compile(r'^(?:\w{3}\s+\d+\s+[\d:]+|<\d+>)')

# ── Deterministic benign pre-classification ───────────────────────────────────
# Phrases that strongly indicate a benign/scheduled activity.
# If ALL conditions in a rule match, mark the alert as benign before LLM.
_BENIGN_PHRASE_SETS = [
    # Scheduled CI/CD or deployment service accounts
    {"scheduled", "deploy"},
    {"ci/cd", "deploy"},
    {"scheduled", "publickey"},
    # Nessus / vulnerability scanner activity
    {"nessus", "scan"},
    {"vulnerability scan", "scheduled"},
    # Routine cron jobs with known-safe commands
    {"cron", "curl", "update"},
]

def _is_deterministic_benign(raw: str) -> bool:
    """
    Returns True if the alert text matches a known-benign phrase pattern.
    Used to short-circuit LLM misclassification on obvious false positives.
    """
    lower = raw.lower()
    for phrase_set in _BENIGN_PHRASE_SETS:
        if all(p in lower for p in phrase_set):
            return True
    return False

# EDR vendors often emit JSON with these top-level keys
_EDR_KEYS = {"event_type", "process_name", "pid", "parent_pid",
             "command_line", "file_hash", "endpoint_id"}


def _detect_source(raw: str) -> str:
    """Heuristic detection of alert origin."""
    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            if _EDR_KEYS & set(obj.keys()):
                return config.ALERT_SOURCE_EDR
            if "alert" in obj or "signature" in obj or "rule" in obj:
                return config.ALERT_SOURCE_IDS
            if "event_id" in obj or "winlog" in obj:
                return config.ALERT_SOURCE_SIEM
        except json.JSONDecodeError:
            pass
    if _RE_SYSLOG.match(stripped):
        return config.ALERT_SOURCE_SYSLOG
    return config.ALERT_SOURCE_MANUAL


def _extract_metadata(raw: str) -> dict:
    """Pull structured fields out of the alert text."""
    meta: dict = {}

    # Try JSON parse first
    stripped = raw.strip()
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
            meta.update({k: v for k, v in obj.items()
                         if isinstance(v, (str, int, float, bool))})
        except json.JSONDecodeError:
            pass

    # Regex overlays (always run — catch fields even from JSON text)
    ips = list(set(_RE_IP.findall(raw)))
    if ips:
        meta["ip_addresses"] = ips

    hashes = list(set(_RE_HASH.findall(raw)))
    if hashes:
        meta["file_hashes"] = hashes

    cves = list(set(_RE_CVE.findall(raw)))
    if cves:
        meta["cve_references"] = cves

    mitre_ids = list(set(_RE_MITRE.findall(raw)))
    if mitre_ids:
        meta["mitre_hints"] = mitre_ids

    ts_match = _RE_TS_ISO.search(raw)
    if ts_match:
        meta["event_timestamp"] = ts_match.group()

    return meta


def intake_node(state: AlertState) -> dict:
    """
    Intake node.
    Input:  state['raw_alert']
    Output: alert_id, alert_source, alert_metadata
    """
    raw = state.get("raw_alert", "").strip()
    if not raw:
        return {
            "error":      "No alert text provided",
            "error_node": "intake",
        }

    alert_id     = state.get("alert_id") or f"ALERT-{uuid.uuid4().hex[:8].upper()}"
    alert_source = _detect_source(raw)
    metadata     = _extract_metadata(raw)

    # Deterministic benign pre-check — tag in metadata so analyze node can fast-path
    if _is_deterministic_benign(raw):
        metadata["deterministic_benign"] = True

    return {
        "alert_id":       alert_id,
        "alert_source":   alert_source,
        "alert_metadata": metadata,
        "pipeline_version": config.PIPELINE_VERSION,
        "retrieval_attempts": 0,
    }
