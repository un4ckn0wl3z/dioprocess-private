from __future__ import annotations

import requests

from .config import get_settings


class BackendClient:
    def __init__(self) -> None:
        self._settings = get_settings()
        if not self._settings.service_key:
            raise RuntimeError("RAG_MCP_SERVICE_KEY is required for MCP server")

    def _headers(self) -> dict[str, str]:
        return {
            "Authorization": f"Bearer {self._settings.service_key}",
            "Content-Type": "application/json",
        }

    def retrieve_internal_skill(self, query: str, top_k: int = 8) -> dict:
        r = requests.post(
            f"{self._settings.backend_url}/v1/rag/query",
            json={"query": query, "top_k": top_k},
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def list_skill_sections(self) -> dict:
        r = requests.get(
            f"{self._settings.backend_url}/v1/rag/sections",
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()

    def cite_sources(self, chunk_ids: list[str]) -> dict:
        r = requests.post(
            f"{self._settings.backend_url}/v1/rag/cite",
            json={"chunk_ids": chunk_ids},
            headers=self._headers(),
            timeout=30,
        )
        r.raise_for_status()
        return r.json()
