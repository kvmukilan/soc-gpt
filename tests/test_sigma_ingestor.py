from pathlib import Path
import pytest
from soc_gpt.sigma_ingestor import parse_rule, convert_to_es_query, load_rules_from_content

SAMPLE_RULE = """
title: Test Sudo Rule
id: test-0001
status: stable
tags:
  - attack.privilege_escalation
  - attack.T1548.003
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    exe|contains:
      - sudo
    cmdline|contains:
      - '-l'
  condition: selection
level: high
"""

def test_load_rules_from_content():
    rule = load_rules_from_content(SAMPLE_RULE, "test_rule")
    assert rule["title"] == "Test Sudo Rule"
    assert rule["level"] == "high"
    assert rule["status"] == "stable"
    assert "attack.T1548.003" in rule["tags"]

def test_convert_to_es_query():
    rule = load_rules_from_content(SAMPLE_RULE, "test_rule")
    query = rule["es_query"]
    assert "query" in query
    assert "bool" in query["query"]
