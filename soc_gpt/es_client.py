from __future__ import annotations

import logging
from typing import Any

from elasticsearch import Elasticsearch, helpers

from soc_gpt.config import settings

logger = logging.getLogger(__name__)

class ESClient:
    def __init__(self, url: str | None = None):
        self._url = url or settings.ES_URL
        self._client = Elasticsearch(self._url, request_timeout=30)

    def ping(self) -> bool:
        try:
            return self._client.ping()
        except Exception:
            return False

    def ensure_index(self, name: str) -> None:
        if not self._client.indices.exists(index=name):
            self._client.indices.create(
                index=name,
                body={
                    "settings": {"number_of_shards": 1, "number_of_replicas": 0},
                    "mappings": {"dynamic": True},
                },
            )
            logger.info("Created index %s", name)

    def bulk_ingest(self, logs: list[dict[str, Any]], index: str) -> int:
        self.ensure_index(index)
        actions = [{"_index": index, "_source": doc} for doc in logs]
        success, errors = helpers.bulk(self._client, actions, raise_on_error=False)
        if errors:
            logger.warning("Bulk ingest had %d errors", len(errors))
        self._client.indices.refresh(index=index)
        return success

    def search(self, query: dict[str, Any], index: str) -> list[dict[str, Any]]:
        try:
            resp = self._client.search(index=index, body=query, size=100)
            return [hit["_source"] for hit in resp["hits"]["hits"]]
        except Exception as exc:
            logger.error("ES search failed: %s", exc)
            return []

    def count(self, index: str) -> int:
        try:
            return self._client.count(index=index)["count"]
        except Exception:
            return 0

_client: ESClient | None = None

def get_client() -> ESClient:
    global _client
    if _client is None:
        _client = ESClient()
    return _client
