from __future__ import annotations
"""Tests for intake node — source detection, metadata extraction, alert ID assignment."""
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import pytest
from pipeline.nodes.intake import intake_node


def test_edr_json_source_detected():
    state = {"raw_alert": '{"event_type":"process","process_name":"cmd.exe","endpoint_id":"WIN-01"}'}
    result = intake_node(state)
    assert result["alert_source"] == "edr"


def test_syslog_source_detected():
    state = {"raw_alert": "Mar 15 10:00:01 server sshd[1234]: Accepted publickey for root"}
    result = intake_node(state)
    assert result["alert_source"] == "syslog"


def test_alert_id_assigned():
    state = {"raw_alert": "Some alert text"}
    result = intake_node(state)
    assert result["alert_id"].startswith("ALERT-")


def test_alert_id_preserved_if_provided():
    state = {"raw_alert": "Some alert text", "alert_id": "ALERT-CUSTOM-01"}
    result = intake_node(state)
    assert result["alert_id"] == "ALERT-CUSTOM-01"


def test_ip_extracted_from_alert():
    state = {"raw_alert": "Connection from 192.168.1.100 to 10.0.0.5:443"}
    result = intake_node(state)
    meta = result.get("alert_metadata", {})
    assert "192.168.1.100" in meta.get("ip_addresses", [])


def test_cve_extracted():
    state = {"raw_alert": "Exploit attempt for CVE-2021-44228 detected on PROD-01"}
    result = intake_node(state)
    meta = result.get("alert_metadata", {})
    assert "CVE-2021-44228" in meta.get("cve_references", [])


def test_empty_alert_returns_error():
    state = {"raw_alert": ""}
    result = intake_node(state)
    assert result.get("error") is not None
    assert result.get("error_node") == "intake"
