from __future__ import annotations
"""
AgentReliabilityLab — Configuration
All settings backed by environment variables with sensible defaults.
"""
import os

# ── LLM ──────────────────────────────────────────────────────────────────────
LLM_BASE_URL: str = os.environ.get("LLM_BASE_URL", "http://localhost:1234/v1")
LLM_API_KEY:  str = os.environ.get("LLM_API_KEY",  "lm-studio")
LLM_MODEL:    str = os.environ.get("LLM_MODEL",    "google/gemma-3-4b")
MAX_RETRIES:  int = int(os.environ.get("MAX_RETRIES", 2))

# ── ChromaDB ──────────────────────────────────────────────────────────────────
CHROMA_PERSIST_DIR:  str = os.environ.get("CHROMA_PERSIST_DIR", "./chroma_db")
CHROMA_COLLECTION:   str = os.environ.get("CHROMA_COLLECTION",  "arl_threat_intel")
EMBEDDING_MODEL:     str = os.environ.get("EMBEDDING_MODEL",    "sentence-transformers/all-MiniLM-L6-v2")
RERANKER_MODEL:      str = os.environ.get("RERANKER_MODEL",     "cross-encoder/ms-marco-MiniLM-L-6-v2")

# ── Retrieval ─────────────────────────────────────────────────────────────────
MAX_RETRIEVAL_CHUNKS:   int = int(os.environ.get("MAX_RETRIEVAL_CHUNKS",   8))
MAX_RETRIEVAL_ATTEMPTS: int = int(os.environ.get("MAX_RETRIEVAL_ATTEMPTS", 2))

# ── Confidence thresholds ─────────────────────────────────────────────────────
CONFIDENCE_HIGH_THRESHOLD:   float = float(os.environ.get("CONFIDENCE_HIGH_THRESHOLD",   0.80))
CONFIDENCE_MEDIUM_THRESHOLD: float = float(os.environ.get("CONFIDENCE_MEDIUM_THRESHOLD", 0.55))

# ── Routing ───────────────────────────────────────────────────────────────────
HUMAN_REVIEW_SEVERITIES: set = {"CRITICAL", "HIGH"}

# ── LangSmith (optional) ──────────────────────────────────────────────────────
LANGCHAIN_TRACING_V2: bool = os.environ.get("LANGCHAIN_TRACING_V2", "false").lower() == "true"
LANGCHAIN_PROJECT:     str = os.environ.get("LANGCHAIN_PROJECT",    "agentreliabilitylab")
LANGCHAIN_API_KEY:     str = os.environ.get("LANGCHAIN_API_KEY",    "")

# ── Cache ─────────────────────────────────────────────────────────────────────
REDIS_URL:         str = os.environ.get("REDIS_URL", "")
CACHE_TTL_SECONDS: int = int(os.environ.get("CACHE_TTL_SECONDS", 86400))

# ── Audit ─────────────────────────────────────────────────────────────────────
AUDIT_LOG_DIR: str = os.environ.get("AUDIT_LOG_DIR", "./audit_logs")

# ── Alert sources ─────────────────────────────────────────────────────────────
ALERT_SOURCE_SYSLOG  = "syslog"
ALERT_SOURCE_EDR     = "edr"
ALERT_SOURCE_IDS     = "ids"
ALERT_SOURCE_SIEM    = "siem"
ALERT_SOURCE_MANUAL  = "manual"
ALERT_SOURCE_UNKNOWN = "unknown"

# ── Severity levels ───────────────────────────────────────────────────────────
SEV_CRITICAL = "CRITICAL"
SEV_HIGH     = "HIGH"
SEV_MEDIUM   = "MEDIUM"
SEV_LOW      = "LOW"
SEV_BENIGN   = "BENIGN"
SEV_UNKNOWN  = "UNKNOWN"

SEVERITY_RANK: dict = {
    SEV_CRITICAL: 5, SEV_HIGH: 4, SEV_MEDIUM: 3,
    SEV_LOW: 2, SEV_BENIGN: 1, SEV_UNKNOWN: 0,
}

PIPELINE_VERSION = "1.0.0"
