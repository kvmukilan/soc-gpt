"""False-positive scoring formula and labelling (offline, deterministic)."""

from __future__ import annotations

import pytest

from soc_gpt import fp_scorer


def _hits(n: int) -> list[dict]:
    return [{"i": i} for i in range(n)]


@pytest.mark.parametrize(
    ("level", "status", "n_hits", "expected"),
    [
        ("high", "stable", 3, 1.5),          # 2.5 - 1.0 + 0 (1-5 hits)
        ("medium", "test", 10, 6.0),         # 5.0 + 0 + 1.0 (6-50 hits)
        ("critical", "stable", 100, 3.0),    # 1.0 - 1.0 + 3.0 (>50 hits)
        ("low", "experimental", 0, 9.5),     # 7.5 + 2.0 + 0 (empty)
        ("critical", "stable", 0, 0.0),      # clamp lower bound
        ("low", "deprecated", 100, 10.0),    # 7.5 + 3.0 + 3.0 -> clamp to 10
    ],
)
def test_score_offhours_components(freeze_hour, level, status, n_hits, expected):
    freeze_hour(3)  # 03:00 UTC -> off-hours, no time bump
    rule = {"level": level, "status": status}
    assert fp_scorer.score(rule, _hits(n_hits)) == expected


def test_business_hours_adds_half_point(freeze_hour):
    rule = {"level": "high", "status": "stable"}
    freeze_hour(10)  # 10:00 UTC -> business hours
    assert fp_scorer.score(rule, _hits(3)) == 2.0
    freeze_hour(3)
    assert fp_scorer.score(rule, _hits(3)) == 1.5


def test_unknown_level_and_status_use_defaults(freeze_hour):
    freeze_hour(3)
    rule = {"level": "bogus", "status": "bogus"}
    # default base 5.0 + default delta 0.0 + 0 volume + 0 time
    assert fp_scorer.score(rule, _hits(1)) == 5.0


def test_score_is_deterministic_under_frozen_clock(freeze_hour):
    freeze_hour(12)
    rule = {"level": "high", "status": "test"}
    assert fp_scorer.score(rule, _hits(4)) == fp_scorer.score(rule, _hits(4))


@pytest.mark.parametrize(
    ("value", "expected"),
    [
        (0.0, "Likely True Positive"),
        (3.0, "Likely True Positive"),   # inclusive lower boundary
        (3.01, "Uncertain — Investigate"),
        (6.0, "Uncertain — Investigate"),  # inclusive boundary
        (6.01, "Likely False Positive"),
        (10.0, "Likely False Positive"),
    ],
)
def test_label_thresholds(value, expected):
    assert fp_scorer.label(value) == expected
