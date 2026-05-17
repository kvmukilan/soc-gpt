from __future__ import annotations
from datetime import datetime

_LEVEL_BASE = {
    "critical": 1.0,
    "high": 2.5,
    "medium": 5.0,
    "low": 7.5,
    "informational": 9.0,
}

_STATUS_DELTA = {
    "stable": -1.0,
    "test": 0.0,
    "experimental": 2.0,
    "deprecated": 3.0,
}

def score(rule: dict, hits: list[dict]) -> float:
    base = _LEVEL_BASE.get(rule.get("level", "medium").lower(), 5.0)
    delta = _STATUS_DELTA.get(rule.get("status", "test").lower(), 0.0)

    n = len(hits)
    if n == 0:
        volume_delta = 0.0
    elif n <= 5:
        volume_delta = 0.0
    elif n <= 50:
        volume_delta = 1.0
    else:
        volume_delta = 3.0

    hour = datetime.now().hour
    time_delta = 0.5 if 8 <= hour < 18 else 0.0

    raw = base + delta + volume_delta + time_delta
    return round(max(0.0, min(10.0, raw)), 2)

def label(fp_score: float) -> str:
    if fp_score <= 3.0:
        return "Likely True Positive"
    elif fp_score <= 6.0:
        return "Uncertain — Investigate"
    else:
        return "Likely False Positive"
