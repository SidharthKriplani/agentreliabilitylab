from __future__ import annotations
"""
AgentReliabilityLab — Shared pipeline state + Pydantic models.
AlertState flows through all LangGraph nodes.
"""
from typing import Any, Optional
from typing_extensions import TypedDict
from pydantic import BaseModel, Field


# ── Pydantic output models ────────────────────────────────────────────────────

class TriageAnalysis(BaseModel):
    """Structured output from the LLM analyze node."""
    technique_ids: list[str] = Field(default_factory=list,
        description="MITRE ATT&CK technique IDs, e.g. ['T1059.001', 'T1055']")
    tactics: list[str] = Field(default_factory=list,
        description="MITRE ATT&CK tactic names, e.g. ['Execution', 'Defense Evasion']")
    severity: str = Field(default="UNKNOWN",
        description="CRITICAL | HIGH | MEDIUM | LOW | BENIGN | UNKNOWN")
    severity_rationale: str = Field(default="",
        description="1-2 sentence rationale for the severity assignment")
    ioc_indicators: list[str] = Field(default_factory=list,
        description="Extracted IOC strings (IPs, hashes, domains, processes)")
    recommended_controls: list[str] = Field(default_factory=list,
        description="NIST CSF control IDs or plain-language mitigations")
    policy_citations: list[str] = Field(default_factory=list,
        description="Source chunk IDs cited in the analysis")
    confidence: float = Field(default=0.5, ge=0.0, le=1.0,
        description="Self-reported confidence in this analysis")
    requires_more_context: bool = Field(default=False,
        description="True if agent needs another retrieval pass")


class TokenLog(BaseModel):
    """Tracks token economics across all LLM calls in the pipeline."""
    retrieve_prompt_tokens:     int = 0
    retrieve_completion_tokens: int = 0
    analyze_prompt_tokens:      int = 0
    analyze_completion_tokens:  int = 0
    total_prompt_tokens:        int = 0
    total_completion_tokens:    int = 0
    total_tokens:               int = 0
    cache_hit:                  bool = False

    def update_totals(self) -> None:
        self.total_prompt_tokens = (
            self.retrieve_prompt_tokens + self.analyze_prompt_tokens
        )
        self.total_completion_tokens = (
            self.retrieve_completion_tokens + self.analyze_completion_tokens
        )
        self.total_tokens = self.total_prompt_tokens + self.total_completion_tokens


class RetrievedChunk(BaseModel):
    """A single chunk returned from the RAG layer."""
    chunk_id:   str
    source:     str   # "mitre_attack" | "nist_csf" | "cisa_advisories"
    text:       str
    score:      float = 0.0
    retrieval:  str   = "hybrid"  # "dense" | "bm25" | "hybrid"


# ── LangGraph state ───────────────────────────────────────────────────────────

class AlertState(TypedDict, total=False):
    # ── Intake ─────────────────────────────────────────────────────────────
    raw_alert:        str
    alert_id:         str
    alert_source:     str   # syslog | edr | ids | siem | manual | unknown
    alert_metadata:   dict  # parsed key-value fields from the raw alert

    # ── Retrieval ───────────────────────────────────────────────────────────
    retrieval_query:    str
    retrieved_chunks:   list[dict]
    retrieval_attempts: int

    # ── Analysis ────────────────────────────────────────────────────────────
    analysis:           dict   # TriageAnalysis.model_dump()

    # ── Confidence ──────────────────────────────────────────────────────────
    confidence_score:   float
    confidence_band:    str    # HIGH | MEDIUM | LOW

    # ── Routing ─────────────────────────────────────────────────────────────
    triage_decision:        str        # CRITICAL | HIGH | MEDIUM | LOW | BENIGN
    reason_codes:           list[str]
    human_review_required:  bool
    human_override:         Optional[dict]

    # ── Audit ────────────────────────────────────────────────────────────────
    audit_id:           str
    token_log:          dict
    langsmith_run_id:   Optional[str]
    pipeline_version:   str

    # ── Error ────────────────────────────────────────────────────────────────
    error:              Optional[str]
    error_node:         Optional[str]
