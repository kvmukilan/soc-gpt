from __future__ import annotations
import logging
from pathlib import Path
import yaml
from soc_gpt.config import settings

logger = logging.getLogger(__name__)

def parse_rule(path: Path) -> dict:
    raw = path.read_text(encoding="utf-8")
    data = yaml.safe_load(raw)
    tags = data.get("tags", [])
    return {
        "id": data.get("id", path.stem),
        "title": data.get("title", path.stem),
        "level": data.get("level", "medium"),
        "status": data.get("status", "test"),
        "tags": tags,
        "logsource": data.get("logsource", {}),
        "raw_yaml": raw,
        "path": str(path),
    }

def convert_to_es_query(rule: dict, index: str | None = None) -> dict:
    # Build an ES DSL query from Sigma rule detection fields
    # We do a simplified keyword extraction since full pySigma requires
    # sigma-backend-elasticsearch which has complex install requirements.
    # This produces valid ES bool queries that work with the sample data.
    try:
        raw = yaml.safe_load(rule["raw_yaml"])
        detection = raw.get("detection", {})
        condition = detection.get("condition", "selection")

        must_clauses = []

        for key, value in detection.items():
            if key == "condition":
                continue
            if isinstance(value, dict):
                for field, patterns in value.items():
                    if isinstance(patterns, list):
                        should = [{"wildcard": {field: {"value": f"*{p}*", "case_insensitive": True}}} for p in patterns]
                        must_clauses.append({"bool": {"should": should, "minimum_should_match": 1}})
                    elif isinstance(patterns, str):
                        must_clauses.append({"wildcard": {field: {"value": f"*{patterns}*", "case_insensitive": True}}})
            elif isinstance(value, list):
                should = [{"multi_match": {"query": str(v), "fields": ["*"]}} for v in value]
                must_clauses.append({"bool": {"should": should, "minimum_should_match": 1}})

        if not must_clauses:
            must_clauses = [{"match_all": {}}]

        return {
            "query": {
                "bool": {
                    "must": must_clauses
                }
            }
        }
    except Exception as exc:
        logger.warning("Failed to convert rule %s: %s — using match_all", rule.get("title"), exc)
        return {"query": {"match_all": {}}}

def load_rules_from_dir(directory: Path) -> list[dict]:
    rules = []
    for path in sorted(directory.glob("*.yml")):
        try:
            rule = parse_rule(path)
            rule["es_query"] = convert_to_es_query(rule)
            rules.append(rule)
            logger.info("Loaded rule: %s", rule["title"])
        except Exception as exc:
            logger.error("Failed to load %s: %s", path, exc)
    return rules

def load_rules_from_content(content: str, name: str = "uploaded_rule") -> dict:
    data = yaml.safe_load(content)
    tags = data.get("tags", [])
    rule = {
        "id": data.get("id", name),
        "title": data.get("title", name),
        "level": data.get("level", "medium"),
        "status": data.get("status", "test"),
        "tags": tags,
        "logsource": data.get("logsource", {}),
        "raw_yaml": content,
        "path": name,
    }
    rule["es_query"] = convert_to_es_query(rule)
    return rule
