from __future__ import annotations
"""
Node 2: Hybrid RAG Retrieval
- Builds a contextual query from the alert text + metadata
- Retrieves relevant chunks from MITRE ATT&CK / NIST CSF / CISA advisories
- Uses hybrid retrieval (BM25 + dense) with cross-encoder reranking
- On re-retrieval (attempt > 0) refines query with partial analysis context
"""
import config
from pipeline.state import AlertState, TokenLog


def _build_query(state: AlertState) -> str:
    """
    Construct the retrieval query.
    On first attempt: use raw alert + metadata hints.
    On re-retrieval: incorporate prior analysis context.
    """
    raw      = state.get("raw_alert", "")
    meta     = state.get("alert_metadata", {})
    attempt  = state.get("retrieval_attempts", 0)
    analysis = state.get("analysis", {})

    parts = []

    if attempt == 0:
        # First pass: alert text truncated + key metadata
        parts.append(raw[:800])
        if meta.get("cve_references"):
            parts.append("CVE references: " + ", ".join(meta["cve_references"]))
        if meta.get("mitre_hints"):
            parts.append("MITRE technique hints: " + ", ".join(meta["mitre_hints"]))
        if meta.get("process_name"):
            parts.append(f"Process: {meta['process_name']}")
        if meta.get("command_line"):
            parts.append(f"Command: {meta['command_line'][:200]}")
    else:
        # Re-retrieval: use partial analysis to refine the query
        parts.append("Cyber threat analysis context:")
        if analysis.get("technique_ids"):
            parts.append("Technique IDs: " + ", ".join(analysis["technique_ids"]))
        if analysis.get("tactics"):
            parts.append("Tactics: " + ", ".join(analysis["tactics"]))
        if analysis.get("severity"):
            parts.append(f"Severity: {analysis['severity']}")
        # Also include key alert metadata
        parts.append(raw[:400])

    return " | ".join(parts)


def retrieve_node(state: AlertState) -> dict:
    """
    Retrieval node.
    Input:  state['raw_alert'], state['alert_metadata'], state['retrieval_attempts']
    Output: retrieved_chunks, retrieval_query, retrieval_attempts (incremented)
    """
    if state.get("error"):
        return {}

    query    = _build_query(state)
    attempt  = state.get("retrieval_attempts", 0)
    existing = state.get("token_log", {})

    chunks = []
    try:
        from rag.retriever import retrieve_threat_chunks
        chunks = retrieve_threat_chunks(query, top_k=config.MAX_RETRIEVAL_CHUNKS)
    except Exception as e:
        import sys
        print(f"[retrieve] RAG error (attempt {attempt+1}): {e}", file=sys.stderr)
        # Non-fatal — proceed with empty chunks; analyze node handles it gracefully

    tl = TokenLog(**existing) if existing else TokenLog()
    tl.update_totals()

    return {
        "retrieval_query":    query,
        "retrieved_chunks":   chunks,
        "retrieval_attempts": attempt + 1,
        "token_log":          tl.model_dump(),
    }
