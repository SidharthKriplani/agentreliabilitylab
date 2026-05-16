from __future__ import annotations
"""Pytest fixtures shared across the test suite."""
import pytest


SAMPLE_RANSOMWARE_ALERT = (
    '{"event_type":"process","process_name":"vssadmin.exe",'
    '"command_line":"vssadmin.exe delete shadows /all /quiet",'
    '"parent_process":"cmd.exe","user":"SYSTEM","endpoint_id":"WIN-DC-01"}'
)

SAMPLE_BENIGN_ALERT = (
    "Accepted publickey for deploy from 10.0.0.5. "
    "Scheduled CI/CD deployment."
)

SAMPLE_PHISHING_ALERT = (
    "Email Security Alert: Macro-enabled attachment Invoice.docm from "
    "spoofed domain it-support@c0rp-helpdesk.com. 45 recipients."
)

SAMPLE_LSASS_ALERT = (
    '{"event_type":"process","process_name":"procdump64.exe",'
    '"command_line":"procdump64.exe -ma lsass.exe lsass.dmp",'
    '"parent_process":"powershell.exe","user":"Administrator"}'
)


@pytest.fixture
def ransomware_alert():
    return SAMPLE_RANSOMWARE_ALERT


@pytest.fixture
def benign_alert():
    return SAMPLE_BENIGN_ALERT


@pytest.fixture
def phishing_alert():
    return SAMPLE_PHISHING_ALERT


@pytest.fixture
def lsass_alert():
    return SAMPLE_LSASS_ALERT
