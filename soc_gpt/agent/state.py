from __future__ import annotations

from typing import TypedDict


class TriageState(TypedDict):
    sigma_rules: list[dict]
    es_queries: list[dict]
    raw_matches: list[dict]
    attack_techniques: list[dict]
    fp_scores: list[float]
    triage_report: str
    recommended_actions: list[str]
    status: str
    error: str | None
