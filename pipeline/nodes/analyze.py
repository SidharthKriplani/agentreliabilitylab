from __future__ import annotations
"""
Node 3: LLM Threat Analysis
- Receives alert text + retrieved threat-intel chunks
- Calls LLM to produce a structured TriageAnalysis
- 3-pass JSON recovery (same pattern as LendFlow extract node)
- Sets requires_more_context=True if confidence < threshold AND
  retrieval_attempts < MAX_RETRIEVAL_ATTEMPTS  (triggers re-retrieval loop)
"""
import json
import re
import sys
from typing import Optional

from openai import OpenAI

import config
from pipeline.state import AlertState, TriageAnalysis, TokenLog
from pipeline.cache import get_cached, set_cached


_client = OpenAI(base_url=config.LLM_BASE_URL, api_key=config.LLM_API_KEY)

_SYSTEM_PROMPT = (
    "You are a cyber threat intelligence analyst. "
    "You will be given a security alert and relevant threat-intel excerpts. "
    "Respond with ONLY a JSON object — no markdown, no code fences, no explanation. "
    "Start with { and end with }. "
    "Map the alert to MITRE ATT&CK techniques, assess severity, list IOCs, "
    "and recommend NIST CSF controls. "
    "If you need more context to be confident, set requires_more_context=true. "
    "Fields: technique_ids (list), tactics (list), severity (CRITICAL|HIGH|MEDIUM|LOW|BENIGN|UNKNOWN), "
    "severity_rationale (string), ioc_indicators (list), recommended_controls (list), "
    "policy_citations (list of source chunk IDs), confidence (0.0-1.0), "
    "requires_more_context (bool)."
)

_SCHEMA = TriageAnalysis.model_json_schema()


def _extract_json(text: str) -> dict:
    """3-pass JSON extraction (identical strategy to LendFlow)."""
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    stripped = re.sub(r"^```(?:json)?\s*", "", text.strip(), flags=re.IGNORECASE)
    stripped = re.sub(r"\s*```$", "", stripped.strip())
    try:
        return json.loads(stripped)
    except json.JSONDecodeError:
        pass
    match = re.search(r"\{[\s\S]*\}", text)
    if match:
        try:
            return json.loads(match.group())
        except json.JSONDecodeError:
            pass
    return {}


def _call_llm(user_content: str,
              retries: int = config.MAX_RETRIES) -> tuple[dict, int, int]:
    messages = [
        {"role": "system", "content": _SYSTEM_PROMPT},
        {"role": "user",   "content": user_content},
    ]
    for attempt in range(retries + 1):
        try:
            resp = _client.chat.completions.create(
                model=config.LLM_MODEL,
                messages=messages,
                temperature=0,
            )
            raw = resp.choices[0].message.content or ""
            pt  = resp.usage.prompt_tokens     if resp.usage else 0
            ct  = resp.usage.completion_tokens if resp.usage else 0
            parsed = _extract_json(raw.strip())
            if parsed:
                return parsed, pt, ct
            if attempt < retries:
                messages.append({"role": "assistant", "content": raw})
                messages.append({
                    "role": "user",
                    "content": (
                        "Your response did not contain valid JSON. "
                        "Output ONLY a JSON object. Start with { end with }."
                    ),
                })
        except Exception as e:
            print(f"[analyze] LLM error (attempt {attempt+1}): {e}", file=sys.stderr)
            break
    return {}, 0, 0


def _format_chunks(chunks: list[dict]) -> str:
    if not chunks:
        return "No threat-intel chunks retrieved."
    lines = []
    for i, c in enumerate(chunks[:config.MAX_RETRIEVAL_CHUNKS], 1):
        cid    = c.get("chunk_id", f"chunk_{i}")
        source = c.get("source",   "unknown")
        text   = c.get("text",     "")[:400]
        lines.append(f"[{cid}] ({source})\n{text}")
    return "\n\n".join(lines)


def analyze_node(state: AlertState) -> dict:
    """
    Analyze node.
    Input:  raw_alert, alert_metadata, retrieved_chunks, retrieval_attempts
    Output: analysis (TriageAnalysis dict), updated token_log
    """
    if state.get("error"):
        return {}

    raw      = state.get("raw_alert", "")
    meta     = state.get("alert_metadata", {})
    chunks   = state.get("retrieved_chunks", [])
    attempt  = state.get("retrieval_attempts", 0)
    existing = state.get("token_log", {})

    # ── Deterministic benign fast-path ────────────────────────────────────
    # If intake flagged this as a known-benign pattern, skip the LLM entirely.
    if meta.get("deterministic_benign"):
        tl = TokenLog(**existing) if existing else TokenLog()
        tl.update_totals()
        benign_analysis = TriageAnalysis(
            technique_ids=[], tactics=[], severity="BENIGN",
            severity_rationale="Deterministically classified as benign by intake node "
                               "(matched known-safe pattern: scheduled deployment/scan).",
            ioc_indicators=[], recommended_controls=[],
            policy_citations=[], confidence=0.95,
            requires_more_context=False,
        ).model_dump()
        return {"analysis": benign_analysis, "token_log": tl.model_dump()}


    # ── Cache lookup ─────────────────────────────────────────────────────
    cache_key = raw + str(attempt)
    cached = get_cached(cache_key, "analyze")
    if cached:
        tl = TokenLog(cache_hit=True)
        tl.update_totals()
        return {
            "analysis":  cached["analysis"],
            "token_log": tl.model_dump(),
            "cache_hit": True,
        }

    # ── Build user prompt ────────────────────────────────────────────────
    meta_str = "\n".join(f"  {k}: {v}" for k, v in meta.items()
                         if k not in ("ip_addresses", "file_hashes")) 
    user_content = (
        f"Security alert:\n{raw[:1200]}\n\n"
        f"Extracted metadata:\n{meta_str or '(none)'}\n\n"
        f"JSON schema to match:\n{json.dumps(_SCHEMA, indent=2)}\n\n"
        f"Threat-intel context chunks:\n{_format_chunks(chunks)}\n\n"
        f"Retrieval attempt: {attempt}\n"
        f"Respond with ONLY the JSON object."
    )

    raw_fields, pt, ct = _call_llm(user_content)

    if not raw_fields:
        return {
            "error":      "LLM analysis returned empty result",
            "error_node": "analyze",
        }

    # ── Validate with Pydantic ───────────────────────────────────────────
    try:
        validated = TriageAnalysis.model_validate(raw_fields)
        analysis_dict = validated.model_dump()
    except Exception:
        analysis_dict = raw_fields
        analysis_dict.setdefault("severity",    "UNKNOWN")
        analysis_dict.setdefault("confidence",  0.4)
        analysis_dict.setdefault("requires_more_context", False)

    # ── Should we loop back for more context? ────────────────────────────
    # Only allow one re-retrieval pass to avoid infinite loops
    if (analysis_dict.get("requires_more_context")
            and attempt < config.MAX_RETRIEVAL_ATTEMPTS):
        pass  # graph edge handles the loop; we just preserve requires_more_context=True

    # ── Token log ────────────────────────────────────────────────────────
    tl = TokenLog(**existing) if existing else TokenLog()
    tl.analyze_prompt_tokens     += pt
    tl.analyze_completion_tokens += ct
    tl.update_totals()

    # ── Cache write ──────────────────────────────────────────────────────
    set_cached(cache_key, "analyze", {"analysis": analysis_dict}, {})

    return {
        "analysis":  analysis_dict,
        "token_log": tl.model_dump(),
    }
