from __future__ import annotations
"""
AgentReliabilityLab — FastAPI Application
Endpoints:
  POST /triage              — Submit an alert, run the full pipeline
  POST /human-review/override — Resume a HITL-paused pipeline with officer decision
  GET  /audit/{audit_id}   — Retrieve full audit record
  GET  /health             — Liveness probe
"""
import json
import os
import uuid
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel

import config
from pipeline.graph import run_pipeline

app = FastAPI(
    title="AgentReliabilityLab",
    description="LLM-powered cyber alert triage agent",
    version=config.PIPELINE_VERSION,
)


# ── Request / Response models ─────────────────────────────────────────────────

class TriageRequest(BaseModel):
    raw_alert:   str
    alert_id:    Optional[str] = None
    thread_id:   Optional[str] = None


class TriageResponse(BaseModel):
    alert_id:              str
    audit_id:              Optional[str]
    triage_decision:       Optional[str]
    reason_codes:          list[str]
    technique_ids:         list[str]
    recommended_controls:  list[str]
    confidence_score:      Optional[float]
    confidence_band:       Optional[str]
    human_review_required: bool
    retrieval_attempts:    int
    error:                 Optional[str]
    pipeline_version:      str


class HumanOverrideRequest(BaseModel):
    thread_id:        str
    alert_id:         str
    override_decision: str   # CRITICAL | HIGH | MEDIUM | LOW | BENIGN | DISMISS
    analyst_notes:    Optional[str] = None


# ── Routes ────────────────────────────────────────────────────────────────────

@app.post("/triage", response_model=TriageResponse)
def triage(req: TriageRequest):
    """Submit a raw security alert for triage."""
    alert_id  = req.alert_id or f"ALERT-{uuid.uuid4().hex[:8].upper()}"
    thread_id = req.thread_id or f"thread-{uuid.uuid4().hex[:8]}"

    state = run_pipeline(req.raw_alert, alert_id=alert_id, thread_id=thread_id)

    analysis  = state.get("analysis") or {}
    return TriageResponse(
        alert_id              = state.get("alert_id",              alert_id),
        audit_id              = state.get("audit_id"),
        triage_decision       = state.get("triage_decision"),
        reason_codes          = state.get("reason_codes",          []),
        technique_ids         = analysis.get("technique_ids",      []),
        recommended_controls  = analysis.get("recommended_controls",[]),
        confidence_score      = state.get("confidence_score"),
        confidence_band       = state.get("confidence_band"),
        human_review_required = state.get("human_review_required", False),
        retrieval_attempts    = state.get("retrieval_attempts",    0),
        error                 = state.get("error"),
        pipeline_version      = state.get("pipeline_version", config.PIPELINE_VERSION),
    )


@app.post("/human-review/override")
def human_override(req: HumanOverrideRequest):
    """Record an analyst override for a HITL-paused pipeline run."""
    return {
        "status":    "override_recorded",
        "alert_id":  req.alert_id,
        "decision":  req.override_decision,
        "notes":     req.analyst_notes,
        "message":   (
            "Override recorded. In production this resumes the checkpointed "
            "LangGraph thread via graph.update_state() + graph.stream()."
        ),
    }


@app.get("/audit/{audit_id}")
def get_audit(audit_id: str):
    """Retrieve a full audit record by ID."""
    path = Path(config.AUDIT_LOG_DIR) / f"{audit_id}.json"
    if not path.exists():
        raise HTTPException(status_code=404, detail=f"Audit {audit_id} not found")
    return json.loads(path.read_text())


@app.get("/health")
def health():
    from pipeline.cache import cache_stats
    return {
        "status":           "ok",
        "llm_endpoint":     config.LLM_BASE_URL,
        "llm_model":        config.LLM_MODEL,
        "chroma_collection": config.CHROMA_COLLECTION,
        "langsmith_enabled": config.LANGCHAIN_TRACING_V2,
        "cache":            cache_stats(),
        "pipeline_version": config.PIPELINE_VERSION,
    }
