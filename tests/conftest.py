"""Shared fixtures for the SOC-GPT offline test suite.

Every test in this suite runs with no Elasticsearch, no Ollama, no network and
no secrets. The ``_block_network`` autouse fixture enforces that: any attempt to
open a real socket during a test fails loudly, so a regression that reintroduces
a live dependency cannot pass silently.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path

import pytest

from soc_gpt import sigma_ingestor

DATA_DIR = Path(__file__).resolve().parent.parent / "data"
SIGMA_DIR = DATA_DIR / "sigma_rules"
SAMPLE_LOGS = DATA_DIR / "sample_logs" / "auditd_sample.json"


@pytest.fixture(autouse=True)
def _block_network(monkeypatch):
    """Fail any test that tries to open a real network socket."""

    def _deny(*args, **kwargs):
        raise RuntimeError(
            "Network access is not allowed in the offline test suite"
        )

    monkeypatch.setattr(socket.socket, "connect", _deny)
    monkeypatch.setattr(socket.socket, "connect_ex", _deny)


@pytest.fixture
def sample_events() -> list[dict]:
    """The 50 bundled synthetic auditd events."""
    return json.loads(SAMPLE_LOGS.read_text(encoding="utf-8"))


@pytest.fixture
def sigma_rules() -> list[dict]:
    """The 4 bundled Sigma rules, parsed and converted to ES DSL."""
    return sigma_ingestor.load_rules_from_dir(SIGMA_DIR)


@pytest.fixture
def sudo_rule(sigma_rules) -> dict:
    """The Linux Sudo Privilege Escalation rule (level=high, status=stable)."""
    return next(r for r in sigma_rules if "Sudo" in r["title"])


class FakeES:
    """Minimal stand-in for ESClient that returns canned search results.

    Mirrors the ESClient surface the agent uses (ping/count/search) so it can be
    injected in place of the real Elasticsearch-backed client.
    """

    def __init__(self, results: list[dict]):
        self._results = results

    def ping(self) -> bool:
        return True

    def count(self, index: str) -> int:
        return len(self._results)

    def search(self, query: dict, index: str) -> list[dict]:
        return list(self._results)


@pytest.fixture
def make_es():
    """Factory for a canned Elasticsearch stand-in: ``make_es(results)``."""
    return FakeES


@pytest.fixture
def freeze_hour(monkeypatch):
    """Return ``freeze_hour(hour)`` to pin fp_scorer's UTC clock deterministically."""
    from soc_gpt import fp_scorer

    def _apply(hour: int) -> None:
        class _Frozen(datetime):
            @classmethod
            def now(cls, tz=None):
                return datetime(2026, 1, 1, hour, 0, 0, tzinfo=tz or timezone.utc)

        monkeypatch.setattr(fp_scorer, "datetime", _Frozen)

    return _apply
