from __future__ import annotations
"""
AgentReliabilityLab — LangGraph Agent Assembly

Graph topology:
  intake → retrieve → analyze → [conditional edge] → confidence → route → audit

Conditional edge (the agentic loop):
  If analysis.requires_more_context=True AND retrieval_attempts < MAX:
      → back to retrieve (with refined query)
  Else:
      → confidence

Human-in-the-loop:
  interrupt_before=["audit"] when human_review_required=True.
  Resume via /human-review/override endpoint.
"""
from langgraph.graph import StateGraph, END
from langgraph.checkpoint.memory import MemorySaver

import config
from pipeline.state import AlertState
from pipeline.nodes.intake     import intake_node
from pipeline.nodes.retrieve   import retrieve_node
from pipeline.nodes.analyze    import analyze_node
from pipeline.nodes.confidence import confidence_node
from pipeline.nodes.route      import route_node
from pipeline.nodes.audit      import audit_node


def _should_reretrieve(state: AlertState) -> str:
    """
    Conditional edge after analyze:
    - If requires_more_context AND attempts < max → go back to retrieve
    - Otherwise → proceed to confidence
    """
    if state.get("error"):
        return "confidence"   # skip re-retrieval on error; let it propagate

    analysis  = state.get("analysis", {})
    attempts  = state.get("retrieval_attempts", 0)

    if (analysis.get("requires_more_context")
            and attempts < config.MAX_RETRIEVAL_ATTEMPTS):
        return "retrieve"
    return "confidence"


def _build_base_graph(g: StateGraph) -> StateGraph:
    """Wire up nodes and edges (shared by both graph variants)."""
    g.add_node("intake",     intake_node)
    g.add_node("retrieve",   retrieve_node)
    g.add_node("analyze",    analyze_node)
    g.add_node("confidence", confidence_node)
    g.add_node("route",      route_node)
    g.add_node("audit",      audit_node)

    g.set_entry_point("intake")
    g.add_edge("intake",     "retrieve")
    g.add_edge("retrieve",   "analyze")

    # ── Agentic loop ──────────────────────────────────────────────────────
    g.add_conditional_edges(
        "analyze",
        _should_reretrieve,
        {"retrieve": "retrieve", "confidence": "confidence"},
    )

    g.add_edge("confidence", "route")
    g.add_edge("route",      "audit")
    g.add_edge("audit",      END)
    return g


def build_graph(checkpointer=None):
    """
    Production graph — compiled WITH interrupt_before=["audit"].
    Used by the FastAPI HITL flow: graph pauses before audit when
    human_review_required=True, allowing analyst override.
    """
    cp = checkpointer or MemorySaver()
    return _build_base_graph(StateGraph(AlertState)).compile(
        checkpointer=cp, interrupt_before=["audit"]
    )


def build_graph_no_interrupt(checkpointer=None):
    """
    Demo / eval graph — compiled WITHOUT interrupt_before.
    Audit node always runs; no HITL pause.
    """
    cp = checkpointer or MemorySaver()
    return _build_base_graph(StateGraph(AlertState)).compile(checkpointer=cp)


# Module-level graphs
graph              = build_graph()              # HITL (API)
graph_no_interrupt = build_graph_no_interrupt() # demo / eval / tests


def run_pipeline(raw_alert: str,
                 alert_id: str | None = None,
                 thread_id: str | None = None) -> dict:
    """
    Convenience wrapper — uses the non-interrupt graph so the audit node
    always runs and audit_id is always populated.
    For HITL flows use `graph` directly with a persistent checkpointer.
    """
    import uuid
    tid         = thread_id or f"thread-{uuid.uuid4().hex[:8]}"
    cfg         = {"configurable": {"thread_id": tid}}

    initial: AlertState = {
        "raw_alert": raw_alert,
        "alert_id":  alert_id or f"ALERT-{uuid.uuid4().hex[:8].upper()}",
    }

    final = {}
    for chunk in graph_no_interrupt.stream(initial, config=cfg):
        for _, state_update in chunk.items():
            if isinstance(state_update, dict):
                final.update(state_update)
    return final
