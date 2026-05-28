from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache


@dataclass(frozen=True)
class Settings:
    backend_url: str
    service_key: str
    transport: str
    host: str
    port: int


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    return Settings(
        backend_url=os.getenv("RAG_BACKEND_URL", "http://127.0.0.1:8000"),
        service_key=os.getenv("RAG_MCP_SERVICE_KEY", ""),
        transport=os.getenv("MCP_TRANSPORT", "stdio"),
        host=os.getenv("MCP_HOST", "0.0.0.0"),
        port=int(os.getenv("MCP_PORT", "8001")),
    )
