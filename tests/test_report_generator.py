"""Prompt building and per-rule report generation (offline template path)."""

from __future__ import annotations

from soc_gpt import report_generator
from soc_gpt.llm_client import OllamaClient

_TECHS = [
    {"id": "T1548.003", "name": "Sudo and Sudo Caching"},
]
_HITS = [
    {"cmdline": "sudo -s", "user": "attacker"},
    {"cmdline": "sudo /bin/bash", "user": "www-data"},
    {"cmdline": "sudo su", "user": "root"},
    {"cmdline": "sudo -l", "user": "devops"},  # 4th -> must be dropped from sample
]


def test_build_prompt_includes_alert_context(sudo_rule):
    prompt = report_generator.build_prompt(sudo_rule, _TECHS, _HITS, 1.5)
    assert "Linux Sudo Privilege Escalation" in prompt
    assert "T1548.003 (Sudo and Sudo Caching)" in prompt
    assert "1.5/10 (Likely True Positive)" in prompt
    assert "Matching Events: 4" in prompt
    # Only the first 3 events are sampled into the prompt.
    assert prompt.count("sudo") >= 3
    assert "sudo -l" not in prompt  # the 4th event is excluded
    assert "Executive Summary" in prompt


def test_build_prompt_handles_no_techniques_and_no_hits(sudo_rule):
    prompt = report_generator.build_prompt(sudo_rule, [], [], 5.0)
    assert "ATT&CK Techniques: N/A" in prompt
    assert "No matching events." in prompt


def test_generate_rule_report_uses_template_when_offline(monkeypatch, sudo_rule):
    # Force the "Ollama absent" path end to end through report_generator.
    monkeypatch.setattr(OllamaClient, "is_available", lambda self: False)
    report = report_generator.generate_rule_report(sudo_rule, _TECHS, _HITS, 1.5)

    assert report.startswith("## Linux Sudo Privilege Escalation")
    assert "T1548.003 (Sudo and Sudo Caching)" in report
    assert "**Matches:** 4 events" in report
    assert "1.5/10 — Likely True Positive" in report
    assert "### Recommended SOC Actions" in report
