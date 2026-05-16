from __future__ import annotations
"""
End-to-end pipeline tests with mocked LLM.
Tests that the full graph (intake→retrieve→analyze→confidence→route→audit)
runs without error and produces expected structure.
"""
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from tests.conftest import SAMPLE_RANSOMWARE_ALERT, SAMPLE_BENIGN_ALERT


def _mock_llm_response(technique_ids, severity, confidence=0.85):
    """Build a mock OpenAI response object."""
    content = json.dumps({
        "technique_ids": technique_ids,
        "tactics": ["Impact"],
        "severity": severity,
        "severity_rationale": "Test rationale",
        "ioc_indicators": [],
        "recommended_controls": ["PR.DS-11", "RS.MI-01"],
        "policy_citations": [],
        "confidence": confidence,
        "requires_more_context": False,
    })
    mock_resp = MagicMock()
    mock_resp.choices[0].message.content = content
    mock_resp.usage.prompt_tokens     = 500
    mock_resp.usage.completion_tokens = 150
    return mock_resp


@patch("pipeline.nodes.analyze._client")
def test_ransomware_alert_routes_critical(mock_client, ransomware_alert):
    mock_client.chat.completions.create.return_value = _mock_llm_response(
        ["T1486", "T1490"], "CRITICAL"
    )
    from pipeline.graph import run_pipeline
    state = run_pipeline(ransomware_alert)
    assert state.get("triage_decision") == "CRITICAL"
    assert state.get("human_review_required") is True
    assert state.get("audit_id") is not None
    assert state.get("error") is None


@patch("pipeline.nodes.analyze._client")
def test_benign_alert_routes_benign(mock_client, benign_alert):
    mock_client.chat.completions.create.return_value = _mock_llm_response(
        [], "BENIGN", confidence=0.90
    )
    from pipeline.graph import run_pipeline
    state = run_pipeline(benign_alert)
    assert state.get("triage_decision") == "BENIGN"
    assert state.get("human_review_required") is False


@patch("pipeline.nodes.analyze._client")
def test_state_has_required_fields(mock_client, ransomware_alert):
    mock_client.chat.completions.create.return_value = _mock_llm_response(
        ["T1486"], "CRITICAL"
    )
    from pipeline.graph import run_pipeline
    state = run_pipeline(ransomware_alert)

    required = [
        "alert_id", "alert_source", "triage_decision",
        "confidence_score", "confidence_band",
        "reason_codes", "audit_id", "token_log",
    ]
    for field in required:
        assert field in state, f"Missing field: {field}"


@patch("pipeline.nodes.analyze._client")
def test_confidence_band_assigned(mock_client, ransomware_alert):
    mock_client.chat.completions.create.return_value = _mock_llm_response(
        ["T1486"], "CRITICAL", confidence=0.9
    )
    from pipeline.graph import run_pipeline
    state = run_pipeline(ransomware_alert)
    assert state.get("confidence_band") in ("HIGH", "MEDIUM", "LOW")
    assert 0.0 <= state.get("confidence_score", 0) <= 1.0


@patch("pipeline.nodes.analyze._client")
def test_token_log_populated(mock_client, ransomware_alert):
    mock_client.chat.completions.create.return_value = _mock_llm_response(
        ["T1486"], "CRITICAL"
    )
    from pipeline.graph import run_pipeline
    state = run_pipeline(ransomware_alert)
    tl = state.get("token_log", {})
    assert tl.get("total_tokens", 0) > 0
