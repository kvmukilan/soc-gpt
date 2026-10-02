from __future__ import annotations

import logging

from soc_gpt.agent.state import TriageState
from soc_gpt.attack_mapper import map_rule_techniques
from soc_gpt.config import settings
from soc_gpt.es_client import get_client as get_es
from soc_gpt.fp_scorer import score as fp_score
from soc_gpt.report_generator import generate_rule_report
from soc_gpt.sigma_ingestor import convert_to_es_query

logger = logging.getLogger(__name__)

def parse_sigma_rules(state: TriageState) -> dict:
    rules = state["sigma_rules"]
    queries = []
    for rule in rules:
        if "es_query" not in rule:
            rule["es_query"] = convert_to_es_query(rule)
        queries.append(rule["es_query"])
    return {"es_queries": queries, "status": "Parsed Sigma rules → ES DSL"}

def query_elasticsearch(state: TriageState) -> dict:
    es = get_es()
    matches = []
    for rule, query in zip(state["sigma_rules"], state["es_queries"], strict=True):
        hits = es.search(query, settings.ES_INDEX)
        matches.append({"rule_id": rule["id"], "rule_title": rule["title"], "hits": hits})
        logger.info("Rule '%s': %d hits", rule["title"], len(hits))
    return {"raw_matches": matches, "status": f"Queried Elasticsearch — {sum(len(m['hits']) for m in matches)} total matches"}

def map_attack_techniques(state: TriageState) -> dict:
    techniques = []
    for rule in state["sigma_rules"]:
        techs = map_rule_techniques(rule)
        techniques.append(techs)
    return {"attack_techniques": techniques, "status": "Mapped MITRE ATT&CK techniques"}

def score_false_positives(state: TriageState) -> dict:
    scores = []
    for rule, match in zip(state["sigma_rules"], state["raw_matches"], strict=True):
        s = fp_score(rule, match["hits"])
        scores.append(s)
    return {"fp_scores": scores, "status": "Calculated false-positive scores"}

def generate_triage_report(state: TriageState) -> dict:
    sections = []
    all_actions: list[str] = []

    for rule, match, techs, score in zip(
        state["sigma_rules"],
        state["raw_matches"],
        state["attack_techniques"],
        state["fp_scores"],
        strict=True,
    ):
        report = generate_rule_report(rule, techs, match["hits"], score)
        sections.append(f"---\n# {rule['title']}\n\n{report}")

        # Extract bullet points as recommended actions
        for line in report.splitlines():
            stripped = line.strip()
            if stripped.startswith(("- ", "* ")):
                action = stripped.lstrip("-* ").strip()
                if action and action not in all_actions:
                    all_actions.append(action)

    full_report = "\n\n".join(sections) if sections else "No matching events found for any rule."
    return {
        "triage_report": full_report,
        "recommended_actions": all_actions,
        "status": "Triage report generated",
    }

def no_matches_report(state: TriageState) -> dict:
    return {
        "triage_report": "## No Matches Found\n\nNone of the selected Sigma rules produced any matching log events. Consider ingesting more logs or adjusting rule filters.",
        "recommended_actions": ["Ingest additional log data", "Review rule detection logic"],
        "status": "No matches — triage complete",
    }
