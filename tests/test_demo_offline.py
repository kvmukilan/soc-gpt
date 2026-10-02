"""The offline demo: the whole pipeline with no Elasticsearch and no Ollama.

This is the executable proof behind the README's offline quickstart.
"""

from __future__ import annotations

import soc_gpt.es_client as es_mod
import soc_gpt.llm_client as llm_mod
from soc_gpt import demo


def test_query_matches_is_faithful_to_generated_dsl(sudo_rule):
    query = sudo_rule["es_query"]
    assert demo.query_matches(query, {"exe": "/usr/bin/sudo", "cmdline": "sudo -s"})
    # Benign sudo use that hits no second-group pattern must not match.
    assert not demo.query_matches(query, {"exe": "/usr/bin/sudo", "cmdline": "sudo apt update"})
    # Unrelated activity does not match.
    assert not demo.query_matches(query, {"exe": "/bin/ls", "cmdline": "ls -la /tmp"})


def test_demo_run_produces_real_offline_triage():
    state = demo.run()

    assert state["status"] == "Triage report generated"
    assert len(state["raw_matches"]) == 4
    # In-memory matching yields genuine, non-zero hits for every bundled rule.
    assert all(len(m["hits"]) > 0 for m in state["raw_matches"])

    # ATT&CK enrichment and the template report are present.
    assert "T1059.004" in state["triage_report"]
    assert "### Recommended SOC Actions" in state["triage_report"]
    assert state["recommended_actions"]


def test_demo_run_restores_module_singletons():
    before_es, before_llm = es_mod._client, llm_mod._client
    demo.run()
    assert es_mod._client is before_es
    assert llm_mod._client is before_llm


def test_demo_main_prints_report(capsys):
    demo.main()
    out = capsys.readouterr().out
    assert "no Elasticsearch, no Ollama" in out
    assert "Linux Sudo Privilege Escalation" in out
