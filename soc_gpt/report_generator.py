from __future__ import annotations

from soc_gpt.fp_scorer import label as fp_label
from soc_gpt.llm_client import get_client

_PROMPT_TEMPLATE = """You are a senior SOC analyst writing an alert triage report. Be concise and actionable.

## Alert Details
Rule: {title}
Severity: {level}
ATT&CK Techniques: {techniques}
False-Positive Score: {fp_score}/10 ({fp_label})
Matching Events: {hit_count}

## Sample Matching Events (up to 3)
{sample_events}

## Instructions
Write a triage report with exactly these sections:
1. **Executive Summary** (2 sentences max)
2. **Threat Assessment** (what the attacker may be doing)
3. **False Positive Analysis** (why this may or may not be benign)
4. **Recommended SOC Actions** (bulleted list, 3-5 items)

Use Markdown. Be specific. Do not repeat the alert details verbatim."""

def build_prompt(rule: dict, techniques: list[dict], hits: list[dict], fp_score: float) -> str:
    technique_names = ", ".join(f"{t['id']} ({t['name']})" for t in techniques) or "N/A"
    sample = "\n".join(str(h) for h in hits[:3]) or "No matching events."
    return _PROMPT_TEMPLATE.format(
        title=rule["title"],
        level=rule["level"],
        techniques=technique_names,
        fp_score=fp_score,
        fp_label=fp_label(fp_score),
        hit_count=len(hits),
        sample_events=sample,
    )

def generate_rule_report(rule: dict, techniques: list[dict], hits: list[dict], fp_score: float) -> str:
    prompt = build_prompt(rule, techniques, hits, fp_score)
    technique_names = [f"{t['id']} ({t['name']})" for t in techniques]
    fallback_ctx = {
        "title": rule["title"],
        "techniques": technique_names,
        "fp_score": fp_score,
        "hit_count": len(hits),
    }
    return get_client().generate_with_fallback(prompt, fallback_ctx)
