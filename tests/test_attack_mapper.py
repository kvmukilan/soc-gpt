import pytest
from soc_gpt.attack_mapper import extract_technique_ids, lookup_technique, map_rule_techniques

def test_extract_technique_ids():
    tags = ["attack.privilege_escalation", "attack.T1548.003", "attack.T1059.004"]
    ids = extract_technique_ids(tags)
    assert "T1548.003" in ids
    assert "T1059.004" in ids

def test_lookup_known_technique():
    tech = lookup_technique("T1548.003")
    assert tech["id"] == "T1548.003"
    assert "Sudo" in tech["name"]
    assert tech["tactic"] == "Privilege Escalation"
    assert "url" in tech

def test_lookup_unknown_technique():
    tech = lookup_technique("T9999.999")
    assert tech["id"] == "T9999.999"
    assert "url" in tech

def test_map_rule_techniques():
    rule = {"tags": ["attack.T1053.003", "attack.persistence"]}
    techs = map_rule_techniques(rule)
    assert len(techs) == 1
    assert techs[0]["id"] == "T1053.003"
