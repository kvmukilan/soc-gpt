"""MITRE ATT&CK technique extraction and lookup (offline)."""

from __future__ import annotations

from soc_gpt import attack_mapper


def test_extract_technique_ids_from_sigma_tags():
    tags = ["attack.privilege_escalation", "attack.T1548.003"]
    assert attack_mapper.extract_technique_ids(tags) == ["T1548.003"]


def test_extract_technique_ids_is_case_insensitive_and_deduplicates():
    tags = ["attack.t1059.004", "ATTACK.T1059.004", "attack.execution"]
    assert attack_mapper.extract_technique_ids(tags) == ["T1059.004"]


def test_extract_technique_ids_handles_base_technique_without_subtechnique():
    assert attack_mapper.extract_technique_ids(["attack.T1003"]) == ["T1003"]


def test_lookup_known_technique_returns_full_metadata():
    tech = attack_mapper.lookup_technique("T1059.004")
    assert tech["id"] == "T1059.004"
    assert tech["name"] == "Unix Shell"
    assert tech["tactic"] == "Execution"
    assert tech["url"] == "https://attack.mitre.org/techniques/T1059/004/"


def test_lookup_unknown_technique_falls_back_gracefully():
    tech = attack_mapper.lookup_technique("T9999")
    assert tech["id"] == "T9999"
    assert tech["tactic"] == "Unknown"
    assert tech["url"] == "https://attack.mitre.org/techniques/T9999/"


def test_map_rule_techniques_for_bundled_rule(sudo_rule):
    techs = attack_mapper.map_rule_techniques(sudo_rule)
    assert [t["id"] for t in techs] == ["T1548.003"]
    assert techs[0]["tactic"] == "Privilege Escalation"


def test_map_rule_techniques_with_no_attack_tags_returns_empty():
    rule = {"tags": ["some.other.tag", "attack.lateral_movement"]}
    assert attack_mapper.map_rule_techniques(rule) == []
