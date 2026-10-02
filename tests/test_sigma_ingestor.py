"""Sigma rule ingestion and ES DSL generation (offline)."""

from __future__ import annotations

from soc_gpt import sigma_ingestor

_UPLOAD_YAML = """
title: Test World-Writable Cron
id: test-rule-0001
status: experimental
level: low
tags:
  - attack.persistence
  - attack.T1053.003
logsource:
  product: linux
detection:
  selection:
    cmdline|contains:
      - chmod 777
  condition: selection
"""


def test_load_rules_from_dir_loads_all_four(sigma_rules):
    assert len(sigma_rules) == 4
    # Every loaded rule carries a generated ES query.
    assert all("es_query" in r for r in sigma_rules)
    titles = {r["title"] for r in sigma_rules}
    assert "Linux Sudo Privilege Escalation" in titles


def test_parse_rule_extracts_metadata(sudo_rule):
    assert sudo_rule["level"] == "high"
    assert sudo_rule["status"] == "stable"
    assert "attack.T1548.003" in sudo_rule["tags"]
    assert sudo_rule["raw_yaml"].lstrip().startswith("title:")


def test_convert_to_es_query_builds_bool_must_structure(sudo_rule):
    query = sudo_rule["es_query"]
    must = query["query"]["bool"]["must"]
    # The sudo rule has two detection groups (exe|contains and cmdline|contains),
    # each becoming an OR-group of wildcard clauses.
    assert len(must) == 2
    for clause in must:
        shoulds = clause["bool"]["should"]
        assert clause["bool"]["minimum_should_match"] == 1
        assert all("wildcard" in s for s in shoulds)
    # Patterns are wrapped as case-insensitive *contains* wildcards.
    first_wildcard = next(iter(must[0]["bool"]["should"][0]["wildcard"].values()))
    assert first_wildcard["value"].startswith("*")
    assert first_wildcard["case_insensitive"] is True


def test_convert_to_es_query_empty_detection_falls_back_to_match_all():
    rule = {"raw_yaml": "title: x\ndetection:\n  condition: selection\n"}
    query = sigma_ingestor.convert_to_es_query(rule)
    assert query["query"]["bool"]["must"] == [{"match_all": {}}]


def test_convert_to_es_query_broken_yaml_falls_back_to_match_all():
    rule = {"title": "broken", "raw_yaml": "this: : : not valid yaml ["}
    query = sigma_ingestor.convert_to_es_query(rule)
    assert query == {"query": {"match_all": {}}}


def test_load_rules_from_content_roundtrip():
    rule = sigma_ingestor.load_rules_from_content(_UPLOAD_YAML, "upload.yml")
    assert rule["id"] == "test-rule-0001"
    assert rule["level"] == "low"
    assert rule["status"] == "experimental"
    assert "attack.T1053.003" in rule["tags"]
    assert "es_query" in rule
    # The single detection group yields one must-clause of wildcard shoulds.
    must = rule["es_query"]["query"]["bool"]["must"]
    assert len(must) == 1
