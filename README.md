# SOC-GPT — AI-Augmented SOC Triage Console

A portfolio-quality security tool that combines Sigma detection rules, Elasticsearch log search, MITRE ATT&CK mapping, and a local LLM (Ollama/llama3.2:3b) to produce analyst-ready triage reports — all orchestrated by a LangGraph agent with a live-streaming Streamlit UI.

---

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                        Streamlit UI                             │
│  ┌──────────┐  ┌─────────────┐  ┌─────────────┐  ┌─────────┐  │
│  │   Home   │  │ Sigma Rules │  │Log Ingestor │  │  Triage │  │
│  └──────────┘  └─────────────┘  └─────────────┘  └─────────┘  │
└──────────────────────────┬──────────────────────────────────────┘
                           │ streams agent steps live
┌──────────────────────────▼──────────────────────────────────────┐
│                    LangGraph Agent                              │
│                                                                 │
│  parse_sigma_rules ──► query_elasticsearch                      │
│                              │                                  │
│                    ┌─────────▼──────────┐                       │
│                    │   has matches?     │                       │
│                    └──┬─────────────┬───┘                       │
│                  yes  │             │ no                        │
│          ┌────────────▼──┐    ┌─────▼──────────┐               │
│          │map_attack_    │    │no_matches_     │               │
│          │techniques     │    │report          │               │
│          └────────────┬──┘    └────────────────┘               │
│          ┌────────────▼──┐                                      │
│          │score_false_   │                                      │
│          │positives      │                                      │
│          └────────────┬──┘                                      │
│          ┌────────────▼──┐                                      │
│          │generate_      │                                      │
│          │triage_report  │ ◄── Ollama llama3.2:3b               │
│          └───────────────┘                                      │
└─────────────────────────────────────────────────────────────────┘
         │                                    │
┌────────▼──────────┐              ┌──────────▼──────────┐
│   Elasticsearch   │              │  MITRE ATT&CK DB    │
│   (auditd logs)   │              │  (embedded subset)  │
└───────────────────┘              └─────────────────────┘
```

---

## Tech Stack

| Component          | Technology                          | Purpose                              |
|--------------------|-------------------------------------|--------------------------------------|
| Orchestration      | LangGraph 0.2+                      | Agent state machine with streaming   |
| Detection Rules    | Sigma YAML + pySigma                | Rule ingestion and ES DSL conversion |
| Log Store          | Elasticsearch 8.13                  | Auditd/syslog event storage & search |
| ATT&CK Mapping     | Embedded MITRE DB + mitreattack-python | Technique enrichment               |
| LLM               | Ollama (llama3.2:3b)                | Analyst-ready triage report synthesis|
| UI                 | Streamlit 1.35+                     | Live-streaming multi-page dashboard  |
| Config             | pydantic-settings                   | .env-based configuration             |
| Testing            | pytest + unittest.mock              | Unit + integration tests             |
| Infrastructure     | Docker Compose                      | Elasticsearch, Kibana, Ollama        |

---

## Prerequisites

- Python 3.10+
- Docker Desktop (for Elasticsearch, Kibana, Ollama)
- `make` (optional, for convenience commands)
- ~4 GB RAM for Elasticsearch + Ollama

---

## Setup

### 1. Clone and enter the project

```bash
cd /Users/karmukilan/soc-gpt
```

### 2. Copy environment config

```bash
cp .env.example .env
# Edit .env if your ports differ from defaults
```

### 3. Start infrastructure

```bash
make up
# or: docker compose up -d
```

Wait ~30 seconds for Elasticsearch to become healthy.

### 4. Pull the LLM model

```bash
make pull-model
# or: docker compose exec ollama ollama pull llama3.2:3b
```

This downloads ~2 GB. Do this once.

### 5. Install Python dependencies

```bash
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate
make install
# or: pip install -r requirements-dev.txt
```

### 6. Launch the UI

```bash
make run-ui
# or: streamlit run soc_gpt/ui/app.py
```

Open http://localhost:8501 in your browser.

---

## Usage Walkthrough

### Step 1 — Ingest Sample Logs

1. Navigate to **Log Ingestor** in the sidebar
2. Click **"Load Sample Auditd Logs"**
3. Verify the event count increases (50 synthetic auditd events are indexed)

### Step 2 — Load Detection Rules

1. Navigate to **Sigma Rules**
2. Click **"Load Sample Rules"** to load the 4 bundled rules:
   - Linux Sudo Privilege Escalation (T1548.003)
   - Linux Reverse Shell via Netcat or Bash (T1059.004)
   - Linux Crontab Persistence Mechanism (T1053.003)
   - Linux Sensitive File Access - Passwd Shadow (T1003.008)
3. Expand any rule to see its raw YAML and generated Elasticsearch DSL query

### Step 3 — Run Triage

1. Navigate to **Run Triage**
2. Select which rules to run (all 4 selected by default)
3. Click **"▶ Run Triage"**
4. Watch the agent work through each step live:
   - Parse Sigma rules → ES DSL
   - Query Elasticsearch
   - Map MITRE ATT&CK techniques
   - Score false-positive likelihood
   - Generate triage report (Ollama)
5. Review per-rule summary cards with FP scores, match counts, and ATT&CK links
6. Read the full Markdown analyst report
7. Check off recommended SOC actions

### Step 4 — Upload Custom Rules

On the **Sigma Rules** page, drag-and-drop your own `.yml` Sigma rule files. The agent will automatically convert them to ES DSL.

---

## Running Tests

```bash
make test
# or: pytest tests/ -v
```

Tests use mocked Elasticsearch and Ollama — no running infrastructure required.

---

## Project Structure

```
soc-gpt/
├── data/
│   ├── sigma_rules/          # Bundled Sigma YAML rules (4 rules)
│   └── sample_logs/          # Synthetic auditd events (50 events)
├── soc_gpt/
│   ├── config.py             # pydantic-settings env config
│   ├── es_client.py          # Elasticsearch client wrapper
│   ├── sigma_ingestor.py     # Sigma YAML parsing + ES DSL conversion
│   ├── attack_mapper.py      # MITRE ATT&CK technique lookup
│   ├── fp_scorer.py          # False-positive scoring formula
│   ├── llm_client.py         # Ollama client with template fallback
│   ├── report_generator.py   # Prompt builder + report orchestration
│   ├── agent/
│   │   ├── state.py          # LangGraph TypedDict state schema
│   │   ├── nodes.py          # Agent node functions
│   │   └── graph.py          # StateGraph wiring + conditional edges
│   └── ui/
│       └── app.py            # Streamlit 4-page application
├── tests/
│   ├── test_sigma_ingestor.py
│   ├── test_attack_mapper.py
│   ├── test_fp_scorer.py
│   └── test_agent.py
├── docker-compose.yml        # ES 8.13 + Kibana + Ollama
├── Makefile                  # Convenience targets
├── pyproject.toml
├── requirements.txt
├── requirements-dev.txt
└── .env.example
```

---

## False-Positive Scoring Formula

The FP score (0–10, higher = more likely FP) is computed as:

```
score = base(level) + delta(status) + volume_delta(hit_count) + time_delta(hour)
```

| Component      | Value                                                    |
|----------------|----------------------------------------------------------|
| `base(level)`  | critical=1.0, high=2.5, medium=5.0, low=7.5, info=9.0   |
| `delta(status)`| stable=-1.0, test=0.0, experimental=+2.0, deprecated=+3.0|
| `volume_delta` | 0–5 hits: 0.0 / 6–50 hits: +1.0 / 50+ hits: +3.0       |
| `time_delta`   | Business hours (08:00–18:00): +0.5 / off-hours: 0.0    |

Score interpretation: ≤3.0 → Likely True Positive / 3–6 → Uncertain / >6 → Likely False Positive

---

## Stopping Services

```bash
make down
# or: docker compose down
```

---

## License

MIT — built for portfolio demonstration. Sigma rules included are for educational use.
