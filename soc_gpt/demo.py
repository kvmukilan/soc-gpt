"""Run the full SOC-GPT triage pipeline with no Elasticsearch, no Ollama, no
network and no secrets.

This is the offline quickstart. It loads the bundled Sigma rules and sample
auditd events, evaluates each rule's generated Elasticsearch DSL query in-process
against those events (so per-rule hit counts are *real*, not canned), and runs
the LangGraph agent end to end. Report synthesis uses the Markdown template
fallback because the LLM client is forced to report Ollama as unavailable.

Run it with::

    python -m soc_gpt.demo
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import soc_gpt.es_client as _es_mod
import soc_gpt.llm_client as _llm_mod
from soc_gpt.agent.graph import build_graph
from soc_gpt.agent.state import TriageState
from soc_gpt.llm_client import OllamaClient
from soc_gpt.sigma_ingestor import load_rules_from_dir

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SIGMA_DIR = DATA_DIR / "sigma_rules"
SAMPLE_LOGS = DATA_DIR / "sample_logs" / "auditd_sample.json"


def _event_blob(event: dict[str, Any]) -> str:
    return " ".join(str(v) for v in event.values()).lower()


def _clause_matches(clause: dict[str, Any], blob: str) -> bool:
    """Evaluate one ES DSL leaf/compound clause against an event text blob."""
    if "wildcard" in clause:
        spec = next(iter(clause["wildcard"].values()))
        return str(spec["value"]).strip("*").lower() in blob
    if "bool" in clause:  # should-group: OR across inner clauses
        return any(_clause_matches(s, blob) for s in clause["bool"].get("should", []))
    if "multi_match" in clause:
        return str(clause["multi_match"]["query"]).lower() in blob
    return "match_all" in clause


def query_matches(query: dict[str, Any], event: dict[str, Any]) -> bool:
    """Evaluate a generated bool query against one event (AND across ``must``)."""
    blob = _event_blob(event)
    inner = query.get("query", {})
    bool_q = inner.get("bool")
    if bool_q is None:
        return "match_all" in inner
    return all(_clause_matches(c, blob) for c in bool_q.get("must", []))


class InMemoryES:
    """Drop-in stand-in for :class:`soc_gpt.es_client.ESClient`.

    Honours the bool/must + should structure the Sigma->ES converter emits, so
    the demo exercises the real query-generation and matching logic offline.
    """

    def __init__(self, events: list[dict[str, Any]]):
        self._events = events

    def ping(self) -> bool:
        return True

    def count(self, index: str) -> int:
        return len(self._events)

    def search(self, query: dict[str, Any], index: str) -> list[dict[str, Any]]:
        return [e for e in self._events if query_matches(query, e)]


class _OfflineLLM(OllamaClient):
    """An Ollama client that always reports the server as unavailable, which
    forces :meth:`generate_with_fallback` down the Markdown-template path."""

    def is_available(self) -> bool:
        return False


def load_sample_events() -> list[dict]:
    return json.loads(SAMPLE_LOGS.read_text(encoding="utf-8"))


def run(rules: list[dict] | None = None, events: list[dict] | None = None) -> dict:
    """Run the triage agent fully offline and return the final graph state.

    The in-memory ES store and offline LLM client are injected through the
    existing module-level singletons, then restored, so this is safe to call
    from tests without leaking state.
    """
    rules = rules if rules is not None else load_rules_from_dir(SIGMA_DIR)
    events = events if events is not None else load_sample_events()

    initial_state: TriageState = {
        "sigma_rules": rules,
        "es_queries": [],
        "raw_matches": [],
        "attack_techniques": [],
        "fp_scores": [],
        "triage_report": "",
        "recommended_actions": [],
        "status": "Starting offline demo",
        "error": None,
    }

    saved_es, saved_llm = _es_mod._client, _llm_mod._client
    _es_mod._client = InMemoryES(events)
    _llm_mod._client = _OfflineLLM()
    try:
        return build_graph().invoke(initial_state)
    finally:
        _es_mod._client = saved_es
        _llm_mod._client = saved_llm


def main() -> None:
    state = run()
    print("SOC-GPT offline triage  (no Elasticsearch, no Ollama)")
    print("=" * 56)
    for match, score in zip(state["raw_matches"], state["fp_scores"], strict=True):
        print(f"  {match['rule_title']:<44}{len(match['hits']):>3} hits  FP={score}")
    print("=" * 56)
    print(state["triage_report"])


if __name__ == "__main__":
    main()
