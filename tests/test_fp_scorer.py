import pytest
from soc_gpt.fp_scorer import score, label

@pytest.mark.parametrize("level,status,hits,expected_range", [
    ("critical", "stable", [{}] * 3, (0.0, 4.0)),
    ("high", "stable", [{}] * 3, (0.0, 5.0)),
    ("medium", "test", [{}] * 3, (4.0, 7.0)),
    ("low", "experimental", [{}] * 60, (9.0, 10.0)),
    ("informational", "experimental", [{}] * 100, (10.0, 10.0)),
])
def test_score_range(level, status, hits, expected_range):
    rule = {"level": level, "status": status}
    s = score(rule, hits)
    assert expected_range[0] <= s <= expected_range[1], f"Score {s} not in {expected_range}"

def test_score_clamped():
    rule = {"level": "informational", "status": "experimental"}
    s = score(rule, [{}] * 200)
    assert s == 10.0

def test_label():
    assert label(1.0) == "Likely True Positive"
    assert label(5.0) == "Uncertain — Investigate"
    assert label(8.0) == "Likely False Positive"
