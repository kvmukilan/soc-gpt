"""Ollama client availability check and template fallback (offline).

These tests pin down the headline claim in the README: when Ollama is not
running, report synthesis falls back to a structured Markdown template. No
network is used — ``requests`` is stubbed and the autouse socket guard would
catch any real call.
"""

from __future__ import annotations

import requests

from soc_gpt import llm_client
from soc_gpt.llm_client import OllamaClient

_CTX = {
    "title": "Linux Reverse Shell via Netcat or Bash",
    "techniques": ["T1059.004 (Unix Shell)"],
    "fp_score": 1.0,
    "hit_count": 4,
}


def test_is_available_false_when_server_unreachable(monkeypatch):
    def _boom(*a, **k):
        raise requests.ConnectionError("connection refused")

    monkeypatch.setattr(llm_client.requests, "get", _boom)
    assert OllamaClient().is_available() is False


def test_is_available_true_on_http_200(monkeypatch):
    class _Resp:
        status_code = 200

    monkeypatch.setattr(llm_client.requests, "get", lambda *a, **k: _Resp())
    assert OllamaClient().is_available() is True


def test_fallback_template_used_when_ollama_absent(monkeypatch):
    def _must_not_call(self, prompt):
        raise AssertionError("generate() must not be called when Ollama is absent")

    monkeypatch.setattr(OllamaClient, "is_available", lambda self: False)
    # If anything tried to actually call the model, this would blow up.
    monkeypatch.setattr(OllamaClient, "generate", _must_not_call)
    report = OllamaClient().generate_with_fallback("prompt text", _CTX)

    assert report.startswith("## Linux Reverse Shell via Netcat or Bash")
    assert "T1059.004 (Unix Shell)" in report
    assert "1.0/10 — Likely True Positive" in report  # fp label resolved live
    assert "**Matches:** 4 events" in report
    assert "### Recommended SOC Actions" in report


def test_fallback_when_generate_raises_after_available(monkeypatch):
    monkeypatch.setattr(OllamaClient, "is_available", lambda self: True)

    def _raise(self, prompt):
        raise RuntimeError("model crashed mid-generation")

    monkeypatch.setattr(OllamaClient, "generate", _raise)
    report = OllamaClient().generate_with_fallback("prompt text", _CTX)
    # Resilience: a mid-flight LLM failure still yields the template, not an error.
    assert "### Recommended SOC Actions" in report


def test_get_client_returns_singleton():
    assert llm_client.get_client() is llm_client.get_client()
