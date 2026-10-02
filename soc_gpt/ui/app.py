from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

import streamlit as st

from soc_gpt.agent.graph import graph
from soc_gpt.agent.state import TriageState
from soc_gpt.config import settings
from soc_gpt.es_client import get_client as get_es
from soc_gpt.fp_scorer import label as fp_label
from soc_gpt.sigma_ingestor import load_rules_from_content, load_rules_from_dir

logging.basicConfig(level=logging.INFO)

DATA_DIR = Path(__file__).parent.parent.parent / "data"
SIGMA_DIR = DATA_DIR / "sigma_rules"
SAMPLE_LOGS = DATA_DIR / "sample_logs" / "auditd_sample.json"

st.set_page_config(page_title="SOC-GPT", page_icon="🔍", layout="wide")

# ── Session state initialisation ──────────────────────────────────────────────
if "loaded_rules" not in st.session_state:
    st.session_state.loaded_rules = []
if "last_report" not in st.session_state:
    st.session_state.last_report = None
if "last_triage_time" not in st.session_state:
    st.session_state.last_triage_time = None

# ── Pages ─────────────────────────────────────────────────────────────────────

def page_home():
    st.title("SOC-GPT — AI-Augmented Triage Console")
    st.caption("LangGraph · Elasticsearch · Ollama · MITRE ATT&CK · Sigma")

    es = get_es()
    col1, col2, col3, col4 = st.columns(4)
    with col1:
        alive = es.ping()
        st.metric("Elasticsearch", "🟢 Online" if alive else "🔴 Offline")
    with col2:
        st.metric("Rules Loaded", len(st.session_state.loaded_rules))
    with col3:
        count = es.count(settings.ES_INDEX) if alive else 0
        st.metric("Logs Indexed", count)
    with col4:
        st.metric("Last Triage", st.session_state.last_triage_time or "—")

    st.divider()
    st.subheader("Quick Start")
    st.markdown("""
1. **Start infrastructure**: `docker compose up -d && make pull-model`
2. **Log Ingestor** → Load sample auditd data into Elasticsearch
3. **Sigma Rules** → Load the 4 bundled detection rules
4. **Run Triage** → Select rules and watch the agent work live
    """)

    if st.session_state.last_report:
        st.divider()
        st.subheader("Last Triage Report")
        st.markdown(st.session_state.last_report["triage_report"])


def page_sigma_rules():
    st.title("Sigma Rules")
    st.caption("Upload YAML detection rules or load the bundled sample set")

    col1, col2 = st.columns([2, 1])
    with col1:
        uploaded = st.file_uploader("Upload Sigma YAML rules", type=["yml", "yaml"], accept_multiple_files=True)
    with col2:
        if st.button("Load Sample Rules", use_container_width=True):
            rules = load_rules_from_dir(SIGMA_DIR)
            st.session_state.loaded_rules = rules
            st.success(f"Loaded {len(rules)} sample rules from {SIGMA_DIR}")

    if uploaded:
        new_rules = []
        for f in uploaded:
            try:
                rule = load_rules_from_content(f.read().decode("utf-8"), f.name)
                new_rules.append(rule)
            except Exception as exc:
                st.error(f"Failed to parse {f.name}: {exc}")
        if new_rules:
            st.session_state.loaded_rules.extend(new_rules)
            st.success(f"Loaded {len(new_rules)} rules from upload")

    rules = st.session_state.loaded_rules
    if not rules:
        st.info("No rules loaded yet. Upload YAML files or click 'Load Sample Rules'.")
        return

    st.divider()
    st.subheader(f"{len(rules)} Rules Loaded")

    for rule in rules:
        level_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(rule["level"], "⚪")
        with st.expander(f"{level_color} **{rule['title']}** — `{rule['level']}` / `{rule['status']}`"):
            tags = rule.get("tags", [])
            if tags:
                st.markdown("**Tags:** " + " · ".join(f"`{t}`" for t in tags))

            tab1, tab2 = st.tabs(["Raw Sigma YAML", "Generated ES Query"])
            with tab1:
                st.code(rule["raw_yaml"], language="yaml")
            with tab2:
                import json as _json
                st.code(_json.dumps(rule.get("es_query", {}), indent=2), language="json")


def page_log_ingestor():
    st.title("Log Ingestor")
    st.caption("Index auditd/syslog JSON events into Elasticsearch")

    es = get_es()
    if not es.ping():
        st.error("Elasticsearch is offline. Start it with `docker compose up -d`.")
        return

    col1, col2 = st.columns([2, 1])
    with col1:
        uploaded = st.file_uploader("Upload JSON log file (array of events)", type=["json"])
    with col2:
        if st.button("Load Sample Auditd Logs", use_container_width=True):
            if SAMPLE_LOGS.exists():
                logs = json.loads(SAMPLE_LOGS.read_text())
                n = es.bulk_ingest(logs, settings.ES_INDEX)
                st.success(f"Indexed {n} events into `{settings.ES_INDEX}`")
            else:
                st.error(f"Sample file not found: {SAMPLE_LOGS}")

    if uploaded:
        try:
            logs = json.loads(uploaded.read().decode("utf-8"))
            if not isinstance(logs, list):
                logs = [logs]
            n = es.bulk_ingest(logs, settings.ES_INDEX)
            st.success(f"Indexed {n} events into `{settings.ES_INDEX}`")
        except Exception as exc:
            st.error(f"Failed to ingest: {exc}")

    st.divider()
    st.subheader("Index Stats")
    count = es.count(settings.ES_INDEX)
    st.metric("Total Documents", count)

    if count > 0:
        sample = es.search({"query": {"match_all": {}}, "size": 5}, settings.ES_INDEX)  # type: ignore[arg-type]
        if sample:
            st.subheader("Recent Events (first 5)")
            st.dataframe(sample, use_container_width=True)


def page_run_triage():
    st.title("Run Triage")
    st.caption("Select Sigma rules, trigger the LangGraph agent, and watch it work live")

    rules = st.session_state.loaded_rules
    if not rules:
        st.warning("No rules loaded. Go to **Sigma Rules** and load some first.")
        return

    es = get_es()
    if not es.ping():
        st.error("Elasticsearch is offline. Start it with `docker compose up -d`.")
        return

    rule_titles = [r["title"] for r in rules]
    selected_titles = st.multiselect("Select rules to run", rule_titles, default=rule_titles)
    selected_rules = [r for r in rules if r["title"] in selected_titles]

    if not selected_rules:
        st.info("Select at least one rule to run triage.")
        return

    if st.button("▶ Run Triage", type="primary", use_container_width=True):
        initial_state: TriageState = {
            "sigma_rules": selected_rules,
            "es_queries": [],
            "raw_matches": [],
            "attack_techniques": [],
            "fp_scores": [],
            "triage_report": "",
            "recommended_actions": [],
            "status": "Starting…",
            "error": None,
        }

        final_state = initial_state.copy()

        step_labels = {
            "parse_sigma_rules": "🔍 Parsing Sigma rules → ES DSL",
            "query_elasticsearch": "⚡ Querying Elasticsearch",
            "map_attack_techniques": "🗺️ Mapping MITRE ATT&CK techniques",
            "score_false_positives": "📊 Scoring false-positive likelihood",
            "generate_triage_report": "🤖 Generating triage report (Ollama)",
            "no_matches_report": "📭 No matches found",
        }

        with st.status("Running triage agent…", expanded=True) as status_box:
            for event in graph.stream(initial_state):
                for node_name, node_output in event.items():
                    label = step_labels.get(node_name, node_name)
                    st.write(label)
                    if isinstance(node_output, dict):
                        final_state.update(node_output)
                        if "status" in node_output:
                            status_box.update(label=node_output["status"])

            status_box.update(label="✅ Triage complete", state="complete")

        # SOC dashboards use UTC/Zulu time; also keeps the call timezone-aware.
        st.session_state.last_triage_time = datetime.now(tz=timezone.utc).strftime("%H:%M:%S UTC")
        st.session_state.last_report = final_state

        st.divider()
        st.subheader("Triage Results")

        # Per-rule summary cards
        for i, rule in enumerate(selected_rules):
            matches = final_state["raw_matches"][i] if i < len(final_state["raw_matches"]) else {"hits": []}
            score = final_state["fp_scores"][i] if i < len(final_state["fp_scores"]) else 5.0
            techs = final_state["attack_techniques"][i] if i < len(final_state["attack_techniques"]) else []
            hits = matches.get("hits", [])

            level_color = {"critical": "🔴", "high": "🟠", "medium": "🟡", "low": "🔵"}.get(rule["level"], "⚪")
            with st.expander(f"{level_color} **{rule['title']}** — {len(hits)} matches", expanded=True):
                c1, c2, c3 = st.columns(3)
                c1.metric("FP Score", f"{score}/10", delta=fp_label(score), delta_color="off")
                c2.metric("Matches", len(hits))
                c3.metric("Severity", rule["level"].capitalize())

                if techs:
                    st.markdown("**ATT&CK:** " + " · ".join(f"[{t['id']} — {t['name']}]({t['url']})" for t in techs))

                if hits:
                    with st.expander("Raw matching events"):
                        st.dataframe(hits[:20], use_container_width=True)

        st.divider()
        st.subheader("Full Analyst Report")
        st.markdown(final_state["triage_report"])

        if final_state["recommended_actions"]:
            st.divider()
            st.subheader("Recommended SOC Actions")
            for action in final_state["recommended_actions"]:
                st.checkbox(action, value=False)


# ── Navigation ────────────────────────────────────────────────────────────────

pages = {
    "Home": page_home,
    "Sigma Rules": page_sigma_rules,
    "Log Ingestor": page_log_ingestor,
    "Run Triage": page_run_triage,
}

with st.sidebar:
    st.title("SOC-GPT")
    st.caption("AI-Augmented Triage Console")
    st.divider()
    selection = st.radio("Navigate", list(pages.keys()), label_visibility="collapsed")

pages[selection]()
