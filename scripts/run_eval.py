from __future__ import annotations
"""
AgentReliabilityLab — Full Evaluation Harness
Runs all 20 synthetic alerts through the pipeline and computes:
  - Triage accuracy (correct CRITICAL/HIGH/MEDIUM/LOW/BENIGN)
  - Severity accuracy
  - MITRE technique recall (fraction of GT techniques detected)
  - Latency (avg, p95)
  - Token economics
"""
import json
import os
import sys
import time
from pathlib import Path

# Ensure project root is in path
sys.path.insert(0, str(Path(__file__).parent.parent))

import config
from pipeline.graph import run_pipeline

FIXTURES_DIR = Path(__file__).parent.parent / "eval" / "fixtures"
RESULTS_FILE = Path(__file__).parent.parent / "eval_results.json"


def _load_fixtures() -> list[dict]:
    fixtures = []
    for gt_file in sorted(FIXTURES_DIR.glob("*_gt.json")):
        alert_id  = gt_file.stem.replace("_gt", "")
        alert_file = FIXTURES_DIR / f"{alert_id}.txt"
        if not alert_file.exists():
            continue
        gt = json.loads(gt_file.read_text())
        fixtures.append({
            "alert_id":    alert_id,
            "raw_alert":   alert_file.read_text(),
            "ground_truth": gt,
        })
    return fixtures


def _technique_recall(predicted: list, ground_truth: list) -> float:
    """Fraction of GT MITRE technique IDs (prefix-matched) found in predictions."""
    if not ground_truth:
        return 1.0  # benign — no techniques expected
    pred_prefixes = {t.split(".")[0].upper() for t in predicted}
    gt_prefixes   = {t.split(".")[0].upper() for t in ground_truth}
    if not gt_prefixes:
        return 1.0
    return len(pred_prefixes & gt_prefixes) / len(gt_prefixes)


def main():
    fixtures = _load_fixtures()
    if not fixtures:
        print("[eval] No fixtures found. Run: python scripts/generate_test_alerts.py")
        sys.exit(1)

    print(f"[eval] Running {len(fixtures)} alerts...\n")

    results     = []
    correct_triage   = 0
    correct_severity = 0
    total_recall     = 0.0
    latencies        = []

    for fx in fixtures:
        t0 = time.time()
        try:
            state = run_pipeline(fx["raw_alert"], alert_id=fx["alert_id"])
            elapsed = time.time() - t0

            gt   = fx["ground_truth"]
            pred = {
                "triage_decision": state.get("triage_decision", "UNKNOWN"),
                "severity":        (state.get("analysis") or {}).get("severity", "UNKNOWN"),
                "technique_ids":   (state.get("analysis") or {}).get("technique_ids", []),
            }

            triage_ok   = pred["triage_decision"] == gt["triage_decision"]
            severity_ok = pred["severity"].upper() == gt["severity"].upper()
            recall      = _technique_recall(pred["technique_ids"], gt.get("technique_ids", []))

            if triage_ok:   correct_triage   += 1
            if severity_ok: correct_severity += 1
            total_recall += recall
            latencies.append(elapsed)

            results.append({
                "alert_id":        fx["alert_id"],
                "status":          "ok",
                "triage_correct":  triage_ok,
                "severity_correct": severity_ok,
                "technique_recall": round(recall, 3),
                "predicted":       pred,
                "ground_truth":    gt,
                "latency_s":       round(elapsed, 2),
                "token_log":       state.get("token_log", {}),
                "audit_id":        state.get("audit_id"),
                "error":           state.get("error"),
            })
            status = "✅" if triage_ok else "❌"
            print(f"  {status} {fx['alert_id']}: {pred['triage_decision']:8s} "
                  f"(GT: {gt['triage_decision']:8s}) | "
                  f"recall={recall:.0%} | {elapsed:.1f}s")

        except Exception as e:
            elapsed = time.time() - t0
            latencies.append(elapsed)
            results.append({
                "alert_id": fx["alert_id"],
                "status":   "error",
                "error":    str(e),
                "latency_s": round(elapsed, 2),
            })
            print(f"  💥 {fx['alert_id']}: ERROR — {e}")

    n = len(fixtures)
    avg_lat = sum(latencies) / len(latencies) if latencies else 0
    sorted_lat = sorted(latencies)
    p95_lat = sorted_lat[int(len(sorted_lat) * 0.95)] if latencies else 0

    summary = {
        "total":                n,
        "triage_accuracy":      round(correct_triage   / n, 3),
        "severity_accuracy":    round(correct_severity / n, 3),
        "avg_technique_recall": round(total_recall     / n, 3),
        "avg_latency_s":        round(avg_lat, 2),
        "p95_latency_s":        round(p95_lat, 2),
        "results":              results,
    }

    RESULTS_FILE.write_text(json.dumps(summary, indent=2))

    print(f"\n{'='*55}")
    print(f"  Triage accuracy:       {summary['triage_accuracy']:.1%}  ({correct_triage}/{n})")
    print(f"  Severity accuracy:     {summary['severity_accuracy']:.1%}  ({correct_severity}/{n})")
    print(f"  MITRE technique recall:{summary['avg_technique_recall']:.1%}")
    print(f"  Avg latency:           {summary['avg_latency_s']:.1f}s")
    print(f"  P95 latency:           {summary['p95_latency_s']:.1f}s")
    print(f"{'='*55}")
    print(f"  Results saved to: {RESULTS_FILE}")


if __name__ == "__main__":
    main()
