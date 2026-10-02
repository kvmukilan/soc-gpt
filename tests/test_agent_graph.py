"""End-to-end LangGraph agent runs with a mocked Elasticsearch client (offline).

Exercises both conditional branches of the graph:
  * matches found  -> map ATT&CK -> score -> generate report
  * no matches     -> no_matches_report

The Elasticsearch client is replaced with a canned stand-in and Ollama is forced
offline, so report synthesis uses the Markdown template.
"""

from __future__ import annotations

from soc_gpt.agent import nodes
from soc_gpt.agent.graph import _has_matches, build_graph
from soc_gpt.llm_client import OllamaClient


def _initial_state(rules):
    return {
        "sigma_rules": rules,
        "es_queries": [],
        "raw_matches": [],
        "attack_techniques": [],
        "fp_scores": [],
        "triage_report": "",
        "recommended_actions": [],
        "status": "start",
        "error": None,
    }


def _run(monkeypatch, rules, es):
    monkeypatch.setattr(nodes, "get_es", lambda: es)
    monkeypatch.setattr(OllamaClient, "is_available", lambda self: False)
    return build_graph().invoke(_initial_state(rules))


def test_graph_matches_branch(monkeypatch, sigma_rules, sample_events, make_es):
    es = make_es(sample_events[:5])  # canned: every rule returns 5 events
    state = _run(monkeypatch, sigma_rules, es)

    assert state["status"] == "Triage report generated"
    assert len(state["raw_matches"]) == len(sigma_rules)
    assert all(len(m["hits"]) == 5 for m in state["raw_matches"])

    # ATT&CK mapping ran for every rule (all four carry a technique tag).
    assert len(state["attack_techniques"]) == len(sigma_rules)
    assert all(len(t) >= 1 for t in state["attack_techniques"])

    # Scores are produced per rule and stay within the documented 0-10 range.
    assert len(state["fp_scores"]) == len(sigma_rules)
    assert all(0.0 <= s <= 10.0 for s in state["fp_scores"])

    # The report concatenates a section per rule, via the template fallback.
    for rule in sigma_rules:
        assert rule["title"] in state["triage_report"]
    assert "### Recommended SOC Actions" in state["triage_report"]
    assert "No Matches Found" not in state["triage_report"]
    assert state["recommended_actions"]


def test_graph_no_matches_branch(monkeypatch, sigma_rules, make_es):
    es = make_es([])  # every query returns nothing
    state = _run(monkeypatch, sigma_rules, es)

    assert state["status"] == "No matches — triage complete"
    assert state["triage_report"].startswith("## No Matches Found")
    assert state["recommended_actions"] == [
        "Ingest additional log data",
        "Review rule detection logic",
    ]
    # The map/score/report nodes never ran on this branch.
    assert state["attack_techniques"] == []
    assert state["fp_scores"] == []


def test_has_matches_router():
    assert _has_matches({"raw_matches": [{"hits": [{"x": 1}]}]}) == "continue"
    assert _has_matches({"raw_matches": [{"hits": []}]}) == "no_matches"
    assert _has_matches({}) == "no_matches"
