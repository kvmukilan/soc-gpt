from __future__ import annotations
from langgraph.graph import StateGraph, END
from soc_gpt.agent.state import TriageState
from soc_gpt.agent import nodes

def _has_matches(state: TriageState) -> str:
    total = sum(len(m["hits"]) for m in state.get("raw_matches", []))
    return "continue" if total > 0 else "no_matches"

def build_graph() -> StateGraph:
    g = StateGraph(TriageState)

    g.add_node("parse_sigma_rules", nodes.parse_sigma_rules)
    g.add_node("query_elasticsearch", nodes.query_elasticsearch)
    g.add_node("map_attack_techniques", nodes.map_attack_techniques)
    g.add_node("score_false_positives", nodes.score_false_positives)
    g.add_node("generate_triage_report", nodes.generate_triage_report)
    g.add_node("no_matches_report", nodes.no_matches_report)

    g.set_entry_point("parse_sigma_rules")
    g.add_edge("parse_sigma_rules", "query_elasticsearch")
    g.add_conditional_edges(
        "query_elasticsearch",
        _has_matches,
        {"continue": "map_attack_techniques", "no_matches": "no_matches_report"},
    )
    g.add_edge("map_attack_techniques", "score_false_positives")
    g.add_edge("score_false_positives", "generate_triage_report")
    g.add_edge("generate_triage_report", END)
    g.add_edge("no_matches_report", END)

    return g.compile()

graph = build_graph()
