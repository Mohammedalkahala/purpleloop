"""Minimal read-only client for the Wazuh indexer (OpenSearch)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone

import requests
import urllib3

log = logging.getLogger("purpleloop.indexer")


def iso(dt: datetime) -> str:
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:-3] + "Z"


class Indexer:
    def __init__(self, url: str, user: str, password: str, verify_tls: bool = False, timeout: int = 60):
        self.url = url.rstrip("/")
        self.auth = (user, password)
        self.verify = verify_tls
        self.timeout = timeout
        if not verify_tls:
            urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

    def _post(self, path: str, body: dict, params: dict | None = None) -> dict:
        r = requests.post(f"{self.url}/{path}", json=body, params=params, auth=self.auth,
                          verify=self.verify, timeout=self.timeout)
        if r.status_code >= 400:
            raise RuntimeError(f"indexer {path} -> HTTP {r.status_code}: {r.text[:300]}")
        return r.json()

    def ping(self) -> str:
        r = requests.get(self.url, auth=self.auth, verify=self.verify, timeout=10)
        r.raise_for_status()
        return r.json().get("version", {}).get("number", "?")

    @staticmethod
    def _query(qs: str, start: datetime, end: datetime) -> dict:
        return {"bool": {"filter": [
            {"query_string": {"query": qs, "analyze_wildcard": True}},
            {"range": {"timestamp": {"gte": iso(start), "lt": iso(end)}}},
        ]}}

    def count(self, index: str, qs: str, start: datetime, end: datetime) -> int:
        return int(self._post(f"{index}/_count", {"query": self._query(qs, start, end)}).get("count", 0))

    def search(self, index: str, qs: str, start: datetime, end: datetime,
               limit: int = 20000, source: list[str] | None = None) -> list[dict]:
        """All matching docs (oldest first) up to `limit`, via the scroll API."""
        body = {"query": self._query(qs, start, end), "size": min(1000, limit),
                "sort": [{"timestamp": "asc"}]}
        if source:
            body["_source"] = source
        data = self._post(f"{index}/_search", body, params={"scroll": "2m"})
        docs, scroll_id = [], data.get("_scroll_id")
        try:
            while True:
                hits = data.get("hits", {}).get("hits", [])
                docs.extend(h["_source"] for h in hits)
                if not hits or len(docs) >= limit or not scroll_id:
                    break
                data = self._post("_search/scroll", {"scroll": "2m", "scroll_id": scroll_id})
                scroll_id = data.get("_scroll_id", scroll_id)
        finally:
            if scroll_id:
                try:
                    requests.delete(f"{self.url}/_search/scroll", json={"scroll_id": scroll_id},
                                    auth=self.auth, verify=self.verify, timeout=10)
                except requests.RequestException:
                    pass
        return docs[:limit]
