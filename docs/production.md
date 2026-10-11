# Deployment

`python -m pip install -e '.[dev]'` and `python -m build` now use the supported setuptools backend. Wheels include the sample Sigma rules and auditd logs. CI tests those resources after installation outside the source checkout.

For a persistent local stack, run `docker compose --profile console up -d --build`, then `make pull-model`. Open `http://localhost:8501`. The console uses container service names for Elasticsearch and Ollama; host-run clients retain localhost defaults. Elasticsearch now has persistent volume storage. All published ports bind to localhost because this sample Elasticsearch configuration disables authentication. For remote access, use an authenticated TLS gateway and enable Elasticsearch security before exposing its API.

The console image runs as UID 10001 and checks Streamlit's liveness endpoint. Validate the real triage flow after setup: import sample logs, load four bundled rules, run a triage, and inspect the result. LLM/model readiness is separate from HTTP liveness. Back up Elasticsearch data and retain the prior image; `docker compose down` preserves data, while `down -v` deletes it.
