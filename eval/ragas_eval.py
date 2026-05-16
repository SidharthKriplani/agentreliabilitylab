from __future__ import annotations
"""
AgentReliabilityLab — RAGAS Retrieval Quality Evaluation
Measures faithfulness, context_recall, context_precision, answer_relevance
on the retrieved threat-intel chunks vs. expected analysis outputs.
"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.graph import run_pipeline

FIXTURES_DIR = Path(__file__).parent / "fixtures"


def build_ragas_dataset(fixtures: list[dict]) -> dict:
    """
    Build a RAGAS-compatible dataset from pipeline outputs.
    RAGAS expects: question, answer, contexts, ground_truth
    """
    questions, answers, contexts, ground_truths = [], [], [], []

    for fx in fixtures:
        state = run_pipeline(fx["raw_alert"], alert_id=fx["alert_id"])

        analysis  = state.get("analysis", {})
        chunks    = state.get("retrieved_chunks", [])

        question      = f"What is the threat level and MITRE mapping for: {fx['raw_alert'][:200]}"
        answer        = (
            f"Severity: {analysis.get('severity', 'UNKNOWN')}. "
            f"Techniques: {', '.join(analysis.get('technique_ids', []) or ['none'])}. "
            f"Rationale: {analysis.get('severity_rationale', '')}"
        )
        context_texts = [c.get("text", "") for c in chunks]
        gt_answer     = (
            f"Severity: {fx['ground_truth']['triage_decision']}. "
            f"Techniques: {', '.join(fx['ground_truth'].get('technique_ids', []) or ['none'])}."
        )

        questions.append(question)
        answers.append(answer)
        contexts.append(context_texts)
        ground_truths.append(gt_answer)

    return {
        "question":     questions,
        "answer":       answers,
        "contexts":     contexts,
        "ground_truth": ground_truths,
    }


def run_ragas_eval(fixtures: list[dict]) -> dict:
    """Run RAGAS evaluation. Returns metric scores."""
    try:
        from datasets import Dataset
        from ragas import evaluate
        from ragas.metrics import (
            faithfulness, answer_relevancy,
            context_recall, context_precision,
        )
    except ImportError:
        print("[ragas] RAGAS or datasets not installed. "
              "Run: pip install ragas datasets --break-system-packages")
        return {}

    data    = build_ragas_dataset(fixtures)
    dataset = Dataset.from_dict(data)

    result = evaluate(
        dataset,
        metrics=[faithfulness, answer_relevancy, context_recall, context_precision],
    )

    scores = {
        "faithfulness":        round(float(result["faithfulness"]),        3),
        "answer_relevancy":    round(float(result["answer_relevancy"]),    3),
        "context_recall":      round(float(result["context_recall"]),      3),
        "context_precision":   round(float(result["context_precision"]),   3),
    }
    print("\nRAGAS Retrieval Quality Scores:")
    for k, v in scores.items():
        print(f"  {k:25s}: {v:.3f}")
    return scores


if __name__ == "__main__":
    fixtures = []
    for gt_file in sorted(FIXTURES_DIR.glob("*_gt.json")):
        alert_id   = gt_file.stem.replace("_gt", "")
        alert_file = FIXTURES_DIR / f"{alert_id}.txt"
        if alert_file.exists():
            fixtures.append({
                "alert_id":    alert_id,
                "raw_alert":   alert_file.read_text(),
                "ground_truth": json.loads(gt_file.read_text()),
            })

    if not fixtures:
        print("No fixtures found. Run: python scripts/generate_test_alerts.py")
        sys.exit(1)

    run_ragas_eval(fixtures[:5])   # Run on first 5 for speed
