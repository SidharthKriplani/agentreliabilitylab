from __future__ import annotations
"""Tests for route node — severity-to-decision mapping, technique overrides."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from pipeline.nodes.route import route_node


def _make_state(severity, technique_ids=None, band="HIGH", score=0.85):
    return {
        "analysis": {
            "severity":    severity,
            "technique_ids": technique_ids or [],
            "tactics":     [],
        },
        "confidence_band":  band,
        "confidence_score": score,
    }


def test_ransomware_technique_forces_critical():
    state = _make_state("HIGH", technique_ids=["T1486", "T1490"])
    result = route_node(state)
    assert result["triage_decision"] == "CRITICAL"
    assert "CRITICAL_TECHNIQUE_DETECTED" in result["reason_codes"]


def test_benign_severity_maps_to_benign():
    state = _make_state("BENIGN")
    result = route_node(state)
    assert result["triage_decision"] == "BENIGN"
    assert result["human_review_required"] is False


def test_medium_severity_maps_to_medium():
    state = _make_state("MEDIUM")
    result = route_node(state)
    assert result["triage_decision"] == "MEDIUM"
    assert result["human_review_required"] is False


def test_high_severity_requires_human_review():
    state = _make_state("HIGH")
    result = route_node(state)
    assert result["triage_decision"] == "HIGH"
    assert result["human_review_required"] is True


def test_critical_requires_human_review():
    state = _make_state("CRITICAL")
    result = route_node(state)
    assert result["human_review_required"] is True


def test_low_confidence_upgrades_low_to_medium():
    state = _make_state("LOW", band="LOW", score=0.3)
    result = route_node(state)
    # LOW severity + LOW confidence → upgraded to MEDIUM
    assert result["triage_decision"] in ("MEDIUM", "HIGH")


def test_unknown_severity_escalates():
    state = _make_state("UNKNOWN")
    result = route_node(state)
    assert result["triage_decision"] in ("HIGH", "CRITICAL", "MEDIUM")


def test_lateral_movement_technique_detected():
    state = _make_state("MEDIUM", technique_ids=["T1021.001", "T1078"])
    result = route_node(state)
    # T1021 is a HIGH-level technique
    assert result["triage_decision"] in ("HIGH", "CRITICAL")
    assert "LATERAL_MOVEMENT_DETECTED" in result["reason_codes"]
