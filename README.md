# SOC-GPT — AI-Augmented SOC Triage Console

LangGraph agent that ingests Sigma detection rules, queries Elasticsearch for matching auditd/syslog events, maps findings to MITRE ATT&CK, scores false-positive likelihood, and synthesises analyst-ready Markdown triage reports. Live-streaming Streamlit UI shows each agent step as it runs.

> **Ollama is optional.** If the LLM is not running, the app falls back to a structured Markdown template automatically — no configuration needed.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Streamlit UI                             │
│  ┌──────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │
│  │   Home   │  │ Sigma Rules │  │Log Ingestor │  │  Triage │  │
│  └──────────┘  └─────────────┘  └─────────────┘  └─────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ streams steps live
┌──────────────────────────▼──────────────────────────────────────┐
│                      LangGraph Agent                            │
│                                                                 │
│  parse_sigma_rules ──► query_elasticsearch                      │
│                              │                                  │
│                    ┌─────────▼──────────┐                       │
│                    │   has matches?     │                       │
│                    └──┬─────────────┬───┘                       │
│                  yes  │             │  no                       │
│         ┌─────────────▼──┐   ┌──────▼─────────────┐            │
│         │ map_attack_    │   │ no_matches_report  │            │
│         │ techniques     │   └────────────────────┘            │
│         └─────────────┬──┘                                      │
│         ┌─────────────▼──┐                                      │
│         │ score_false_   │                                      │
│         │ positives      │                                      │
│         └─────────────┬──┘                                      │
│         ┌─────────────▼──┐                                      │
│         │ generate_      │ ◄── Ollama llama3.2 (optional)       │
│         │ triage_report  │     falls back to template if absent │
│         └────────────────┘                                      │
└─────────────────────────────────────────────────────────────────┘
        │                                     │
┌───────▼───────────┐               ┌─────────▼──────────┐
│  Elasticsearch    │               │  MITRE ATT&CK DB   │
│  (auditd logs)    │               │  (embedded subset) │
└───────────────────┘               └────────────────────┘
```

---

## Tech Stack

| Component       | Technology                   | Purpose                                    |
|-----------------|------------------------------|--------------------------------------------|
| Orchestration   | LangGraph 0.2+               | Agent state machine with live streaming    |
| Detection Rules | Sigma YAML + pySigma         | Rule parsing and ES DSL conversion         |
| Log Store       | Elasticsearch 8.13           | Auditd/syslog event storage and search     |
| ATT&CK Mapping  | Embedded MITRE DB            | Technique enrichment per rule              |
| LLM             | Ollama llama3.2:3b (optional)| Analyst triage report synthesis            |
| UI              | Streamlit 1.35+              | Live-streaming 4-page dashboard            |
| Config          | pydantic-settings            | `.env`-based configuration                 |
| Infrastructure  | Docker Desktop               | Runs Elasticsearch + Kibana (+ Ollama)     |

---

## Prerequisites (Windows)

| Requirement | Notes |
|-------------|-------|
| Python 3.10+ | [python.org](https://www.python.org/downloads/) — tick "Add to PATH" during install |
| Docker Desktop | [docs.docker.com/desktop/install/windows](https://docs.docker.com/desktop/install/windows/) — required for Elasticsearch |
| Ollama (optional) | [ollama.com/download](https://ollama.com/download) — if you want LLM-powered reports |
| Git | [git-scm.com](https://git-scm.com) |

---

## Setup (Windows)

### 1. Clone the repo

```bat
git clone https://github.com/kvmukilan/soc-gpt.git
cd soc-gpt
```

### 2. Create virtual environment and install dependencies

```bat
python -m venv .venv
.venv\Scripts\activate
pip install -r requirements.txt
```

### 3. Copy environment config

```bat
copy .env.example .env
```

Edit `.env` only if your ports differ from the defaults (they won't need changing for a fresh install).

### 4. Start Elasticsearch

Make sure Docker Desktop is running, then:

```bat
docker compose up -d elasticsearch
```

Wait ~30 seconds. Verify it's healthy:

```bat
curl http://localhost:9200
```

You should see a JSON response with `"status" : "green"` or `"yellow"`.

> **Kibana is optional.** It's in `docker-compose.yml` if you want a UI for the raw logs, but SOC-GPT doesn't need it.

### 5. (Optional) Start Ollama and pull the model

If you have Ollama installed on Windows:

```bat
ollama pull llama3.2:3b
```

This downloads ~2 GB once. If you skip this step, the app uses a structured Markdown template instead — all features still work.

### 6. Launch the UI

```bat
streamlit run soc_gpt/ui/app.py
```

Open **http://localhost:8501** in your browser.

---

## Usage Walkthrough

### Step 1 — Ingest Sample Logs

1. Go to **Log Ingestor** in the sidebar
2. Click **"Load Sample Auditd Logs"**
3. Verify the event count shows **50 events indexed**

The sample set contains synthetic Linux auditd events including sudo privilege escalation, reverse shell attempts, crontab modifications, and `/etc/passwd` reads — mixed with benign activity.

### Step 2 — Load Detection Rules

1. Go to **Sigma Rules**
2. Click **"Load Sample Rules"** — loads the 4 bundled rules:

| Rule | ATT&CK Technique |
|------|-----------------|
| Linux Sudo Privilege Escalation | T1548.003 |
| Linux Reverse Shell via Netcat or Bash | T1059.004 |
| Linux Crontab Persistence | T1053.003 |
| Linux Sensitive File Access (passwd/shadow) | T1003.008 |

3. Expand any rule to see its **raw Sigma YAML** and the **generated Elasticsearch DSL query**

You can also drag-and-drop your own `.yml` Sigma rule files.

### Step 3 — Run Triage

1. Go to **Run Triage**
2. Select which rules to run (all 4 selected by default)
3. Click **▶ Run Triage**
4. Watch each agent step stream live:
   - Parsing Sigma rules → ES DSL
   - Querying Elasticsearch
   - Mapping MITRE ATT&CK techniques
   - Scoring false-positive likelihood
   - Generating triage report
5. Review per-rule cards: **FP score**, **match count**, **ATT&CK technique links**
6. Read the full Markdown analyst report at the bottom
7. Check off recommended SOC actions

---

## False-Positive Scoring

Score is **0–10** where **0 = almost certainly a true positive**, **10 = likely false positive**.

```
score = base(level) + delta(status) + volume_delta(hit_count) + time_delta(hour)
```

| Factor | Values |
|--------|--------|
| `base(level)` | critical=1.0 · high=2.5 · medium=5.0 · low=7.5 · info=9.0 |
| `delta(status)` | stable=−1.0 · test=0.0 · experimental=+2.0 |
| `volume_delta` | 1–5 hits: 0.0 · 6–50 hits: +1.0 · 50+ hits: +3.0 |
| `time_delta` | Business hours 08:00–18:00: +0.5 · off-hours: 0.0 |

Labels: **≤ 3.0** → Likely True Positive · **3–6** → Uncertain · **> 6** → Likely False Positive

---

## Project Structure

```
soc-gpt/
├── data/
│   ├── sigma_rules/          # 4 bundled Linux/auditd Sigma YAML rules
│   └── sample_logs/          # 50 synthetic auditd events (JSON)
├── soc_gpt/
│   ├── config.py             # pydantic-settings env config
│   ├── es_client.py          # Elasticsearch client (bulk ingest, search, ping)
│   ├── sigma_ingestor.py     # Sigma YAML parsing + ES DSL query generation
│   ├── attack_mapper.py      # MITRE ATT&CK technique lookup (embedded DB)
│   ├── fp_scorer.py          # False-positive scoring formula
│   ├── llm_client.py         # Ollama client with Markdown template fallback
│   ├── report_generator.py   # Prompt builder + LLM orchestration
│   ├── agent/
│   │   ├── state.py          # TriageState TypedDict schema
│   │   ├── nodes.py          # LangGraph node functions (one per pipeline step)
│   │   └── graph.py          # StateGraph wiring + conditional edges
│   └── ui/
│       └── app.py            # Streamlit 4-page application
├── docker-compose.yml        # Elasticsearch 8.13 + Kibana + Ollama
├── Makefile                  # Convenience targets (Windows: use commands directly)
├── pyproject.toml
├── requirements.txt
└── .env.example
```

---

## Stopping Services

```bat
docker compose down
```

---

## Environment Variables

All in `.env` (copy from `.env.example`):

| Variable | Default | Description |
|----------|---------|-------------|
| `ES_URL` | `http://localhost:9200` | Elasticsearch URL |
| `ES_INDEX` | `soc-gpt-logs` | Index name for ingested logs |
| `OLLAMA_URL` | `http://localhost:11434` | Ollama server URL |
| `OLLAMA_MODEL` | `llama3.2:3b` | Model to use for report generation |

---

## License

MIT — built for portfolio and educational demonstration.

## Deployment readiness

See [deployment setup, checks, and rollback](docs/production.md).
