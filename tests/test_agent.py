import pytest
from unittest.mock import patch, MagicMock
from soc_gpt.agent.graph import build_graph
from soc_gpt.agent.state import TriageState

SAMPLE_RULE = {
    "id": "test-001",
    "title": "Test Rule",
    "level": "high",
    "status": "stable",
    "tags": ["attack.T1059.004"],
    "logsource": {},
    "raw_yaml": "title: Test Rule\ndetection:\n  selection:\n    exe: bash\n  condition: selection\nlevel: high\nstatus: stable\ntags:\n  - attack.T1059.004",
    "es_query": {"query": {"match_all": {}}},
}

SAMPLE_HITS = [
    {"exe": "/bin/bash", "cmdline": "bash -i", "user": "attacker", "hostname": "server-01"}
]

@patch("soc_gpt.agent.nodes.get_es")
@patch("soc_gpt.agent.nodes.generate_rule_report")
def test_full_graph_with_matches(mock_report, mock_es_factory):
    mock_es = MagicMock()
    mock_es.search.return_value = SAMPLE_HITS
    mock_es_factory.return_value = mock_es
    mock_report.return_value = "## Test Report\n\n**Executive Summary:** Alert triggered.\n\n- Investigate the event\n- Escalate if confirmed"

    g = build_graph()
    initial: TriageState = {
        "sigma_rules": [SAMPLE_RULE],
        "es_queries": [],
        "raw_matches": [],
        "attack_techniques": [],
        "fp_scores": [],
        "triage_report": "",
        "recommended_actions": [],
        "status": "",
        "error": None,
    }
    result = g.invoke(initial)

    assert result["triage_report"] != ""
    assert len(result["raw_matches"]) == 1
    assert result["raw_matches"][0]["hits"] == SAMPLE_HITS
    assert len(result["fp_scores"]) == 1
    assert len(result["attack_techniques"]) == 1
    assert len(result["recommended_actions"]) > 0

@patch("soc_gpt.agent.nodes.get_es")
def test_full_graph_no_matches(mock_es_factory):
    mock_es = MagicMock()
    mock_es.search.return_value = []
    mock_es_factory.return_value = mock_es

    g = build_graph()
    initial: TriageState = {
        "sigma_rules": [SAMPLE_RULE],
        "es_queries": [],
        "raw_matches": [],
        "attack_techniques": [],
        "fp_scores": [],
        "triage_report": "",
        "recommended_actions": [],
        "status": "",
        "error": None,
    }
    result = g.invoke(initial)
    assert "No Matches" in result["triage_report"]
