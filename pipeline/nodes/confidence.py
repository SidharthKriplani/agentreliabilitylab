from __future__ import annotations
"""
Node 4: Confidence Scoring
- Combines LLM self-reported confidence with heuristic signals
- Computes confidence band: HIGH / MEDIUM / LOW
- Flags if human review is needed based on band + severity
"""
import config
from pipeline.state import AlertState


def _heuristic_boost(analysis: dict) -> float:
    """
    Adjust raw LLM confidence with heuristic signals.
    + 0.05 for every MITRE technique ID present (max +0.15)
    + 0.05 for every NIST control recommended (max +0.10)
    - 0.10 if severity is UNKNOWN
    - 0.05 if technique_ids is empty
    """
    delta = 0.0
    tech_ids = analysis.get("technique_ids") or []
    controls = analysis.get("recommended_controls") or []

    delta += min(len(tech_ids) * 0.05, 0.15)
    delta += min(len(controls) * 0.05, 0.10)

    if (analysis.get("severity") or "UNKNOWN").upper() == "UNKNOWN":
        delta -= 0.10
    if not tech_ids:
        delta -= 0.05

    return delta


def confidence_node(state: AlertState) -> dict:
    """
    Confidence node.
    Input:  analysis dict
    Output: confidence_score, confidence_band, human_review_required
    """
    if state.get("error"):
        return {}

    analysis = state.get("analysis", {})
    if not analysis:
        return {
            "confidence_score": 0.3,
            "confidence_band":  "LOW",
            "human_review_required": True,
        }

    base   = float(analysis.get("confidence", 0.5))
    delta  = _heuristic_boost(analysis)
    score  = round(max(0.0, min(1.0, base + delta)), 3)

    if score >= config.CONFIDENCE_HIGH_THRESHOLD:
        band = "HIGH"
    elif score >= config.CONFIDENCE_MEDIUM_THRESHOLD:
        band = "MEDIUM"
    else:
        band = "LOW"

    severity = (analysis.get("severity") or "UNKNOWN").upper()

    # Human review if:
    # - confidence is LOW
    # - OR severity is CRITICAL/HIGH (always want human eyes on top-severity)
    human_review = (
        band == "LOW"
        or severity in config.HUMAN_REVIEW_SEVERITIES
    )

    return {
        "confidence_score":      score,
        "confidence_band":       band,
        "human_review_required": human_review,
    }
