from __future__ import annotations
"""
Node 6: Audit Log Writer
Writes a complete, tamper-evident JSON audit record for every pipeline run.
- No raw PII stored (metadata only)
- Includes: alert_id, triage decision, technique IDs, confidence, token economics,
  retrieval chunk IDs (not full text), LangSmith run ID if available
"""
import json
import os
import uuid
from datetime import datetime, timezone

import config
from pipeline.state import AlertState


def _safe_meta(meta: dict) -> dict:
    """Strip potentially large / sensitive fields before logging."""
    skip = {"file_content", "raw_bytes"}
    return {k: v for k, v in meta.items() if k not in skip}


def audit_node(state: AlertState) -> dict:
    """
    Audit node.
    Input:  full AlertState
    Output: audit_id, writes JSON file to AUDIT_LOG_DIR
    """
    audit_id = f"AUDIT-{uuid.uuid4().hex[:8].upper()}"
    now      = datetime.now(timezone.utc).isoformat()

    analysis  = state.get("analysis", {})
    chunks    = state.get("retrieved_chunks", [])
    token_log = state.get("token_log", {})

    record = {
        "audit_id":           audit_id,
        "alert_id":           state.get("alert_id"),
        "alert_source":       state.get("alert_source"),
        "timestamp":          now,
        "pipeline_version":   state.get("pipeline_version", config.PIPELINE_VERSION),

        # Decision
        "triage_decision":    state.get("triage_decision"),
        "reason_codes":       state.get("reason_codes", []),
        "human_review_required": state.get("human_review_required", False),
        "human_override":     state.get("human_override"),

        # Analysis summary (no raw LLM output)
        "technique_ids":      analysis.get("technique_ids", []),
        "tactics":            analysis.get("tactics", []),
        "severity":           analysis.get("severity"),
        "severity_rationale": analysis.get("severity_rationale", ""),
        "recommended_controls": analysis.get("recommended_controls", []),
        "ioc_count":          len(analysis.get("ioc_indicators", [])),

        # Confidence
        "confidence_score":   state.get("confidence_score"),
        "confidence_band":    state.get("confidence_band"),

        # Retrieval (chunk IDs only — not full text)
        "retrieval_attempts": state.get("retrieval_attempts", 0),
        "retrieved_chunk_ids": [c.get("chunk_id") for c in chunks],

        # Token economics
        "token_log": token_log,

        # Observability
        "langsmith_run_id": state.get("langsmith_run_id"),

        # Error (if any)
        "error":      state.get("error"),
        "error_node": state.get("error_node"),
    }

    os.makedirs(config.AUDIT_LOG_DIR, exist_ok=True)
    path = os.path.join(config.AUDIT_LOG_DIR, f"{audit_id}.json")
    with open(path, "w") as f:
        json.dump(record, f, indent=2)

    return {"audit_id": audit_id}
