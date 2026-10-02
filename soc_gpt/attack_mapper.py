from __future__ import annotations

import logging
import re

logger = logging.getLogger(__name__)

# Technique metadata — embedded subset covering the 4 demo rules + common ones
# Full lookup falls back to ATT&CK website URL
_TECHNIQUE_DB: dict[str, dict] = {
    "T1548": {"name": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation", "description": "Adversaries may bypass elevation controls to elevate process privileges."},
    "T1548.003": {"name": "Sudo and Sudo Caching", "tactic": "Privilege Escalation", "description": "Adversaries may perform sudo caching and/or use the sudoers file to elevate privileges."},
    "T1059": {"name": "Command and Scripting Interpreter", "tactic": "Execution", "description": "Adversaries may abuse command and script interpreters to execute commands."},
    "T1059.004": {"name": "Unix Shell", "tactic": "Execution", "description": "Adversaries may abuse Unix shell commands and scripts for execution. Unix shells are interactive command interpreters used on Linux/macOS."},
    "T1053": {"name": "Scheduled Task/Job", "tactic": "Persistence", "description": "Adversaries may abuse task scheduling functionality to facilitate initial or recurring execution of malicious code."},
    "T1053.003": {"name": "Cron", "tactic": "Persistence", "description": "Adversaries may abuse the cron utility to perform task scheduling for initial or recurring execution of malicious code."},
    "T1003": {"name": "OS Credential Dumping", "tactic": "Credential Access", "description": "Adversaries may attempt to dump credentials to obtain account login and credential material."},
    "T1003.008": {"name": "/etc/passwd and /etc/shadow", "tactic": "Credential Access", "description": "Adversaries may attempt to dump the contents of /etc/passwd and /etc/shadow to enable offline password cracking."},
    "T1078": {"name": "Valid Accounts", "tactic": "Defense Evasion", "description": "Adversaries may obtain and abuse credentials of existing accounts."},
    "T1190": {"name": "Exploit Public-Facing Application", "tactic": "Initial Access", "description": "Adversaries may attempt to exploit a weakness in an internet-facing host or system."},
    "T1110": {"name": "Brute Force", "tactic": "Credential Access", "description": "Adversaries may use brute force techniques to gain access to accounts."},
    "T1021": {"name": "Remote Services", "tactic": "Lateral Movement", "description": "Adversaries may use valid accounts to log into a service specifically designed to accept remote connections."},
}

_ID_PATTERN = re.compile(r"T\d{4}(?:\.\d{3})?", re.IGNORECASE)

def extract_technique_ids(tags: list[str]) -> list[str]:
    ids = []
    for tag in tags:
        matches = _ID_PATTERN.findall(tag)
        ids.extend(m.upper() for m in matches)
    return list(dict.fromkeys(ids))  # deduplicate preserving order

def lookup_technique(tech_id: str) -> dict:
    tech_id = tech_id.upper()
    if tech_id in _TECHNIQUE_DB:
        entry = _TECHNIQUE_DB[tech_id].copy()
        entry["id"] = tech_id
        entry["url"] = f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
        return entry
    # Generic fallback
    return {
        "id": tech_id,
        "name": tech_id,
        "tactic": "Unknown",
        "description": "Refer to MITRE ATT&CK for details.",
        "url": f"https://attack.mitre.org/techniques/{tech_id.replace('.', '/')}/"
    }

def map_rule_techniques(rule: dict) -> list[dict]:
    ids = extract_technique_ids(rule.get("tags", []))
    return [lookup_technique(tid) for tid in ids]
