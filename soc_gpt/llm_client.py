from __future__ import annotations
import logging
import requests
from soc_gpt.config import settings

logger = logging.getLogger(__name__)

_FALLBACK_TEMPLATE = """## {title}

**ATT&CK Techniques:** {techniques}
**FP Score:** {fp_score}/10 — {fp_label}
**Matches:** {hit_count} events

### Executive Summary
Rule `{title}` triggered {hit_count} matching events. The false-positive score of {fp_score}/10 indicates {fp_label}.

### Threat Assessment
This rule maps to {techniques}. Review the matching events for indicators of malicious activity.

### Recommended SOC Actions
- Investigate the matched events and correlate with other telemetry
- Verify whether the activity aligns with known change windows or approved operations
- Escalate to Tier 2 if confirmed malicious
- Document findings in the ticketing system
"""

class OllamaClient:
    def __init__(self, base_url: str | None = None, model: str | None = None):
        self._base_url = (base_url or settings.OLLAMA_URL).rstrip("/")
        self._model = model or settings.OLLAMA_MODEL

    def is_available(self) -> bool:
        try:
            r = requests.get(f"{self._base_url}/api/tags", timeout=3)
            return r.status_code == 200
        except Exception:
            return False

    def generate(self, prompt: str) -> str:
        import ollama as _ollama
        try:
            client = _ollama.Client(host=self._base_url)
            response = client.chat(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
            )
            return response.message.content
        except Exception as exc:
            logger.error("Ollama generation failed: %s", exc)
            raise

    def generate_with_fallback(self, prompt: str, fallback_context: dict) -> str:
        if self.is_available():
            try:
                return self.generate(prompt)
            except Exception:
                pass
        logger.warning("Ollama unavailable — using template fallback")
        from soc_gpt.fp_scorer import label as fp_label
        return _FALLBACK_TEMPLATE.format(
            title=fallback_context.get("title", "Unknown Rule"),
            techniques=", ".join(fallback_context.get("techniques", ["N/A"])),
            fp_score=fallback_context.get("fp_score", 5.0),
            fp_label=fp_label(fallback_context.get("fp_score", 5.0)),
            hit_count=fallback_context.get("hit_count", 0),
        )

_client: OllamaClient | None = None

def get_client() -> OllamaClient:
    global _client
    if _client is None:
        _client = OllamaClient()
    return _client
