from __future__ import annotations

import os
from dataclasses import dataclass
from functools import lru_cache
from typing import Dict, Set


@dataclass(frozen=True)
class KeyPolicy:
    key_id: str
    key_value: str
    scopes: Set[str]


@dataclass(frozen=True)
class Settings:
    backend_host: str
    backend_port: int
    data_path: str
    collection_name: str
    source_file: str
    source_dir: str
    source_mode: str
    chunk_size: int
    chunk_overlap: int
    max_file_bytes: int
    exclude_dirs: Set[str]
    startup_reindex: bool
    api_keys: Dict[str, KeyPolicy]


def _parse_api_keys(raw: str) -> Dict[str, KeyPolicy]:
    parsed: Dict[str, KeyPolicy] = {}
    for item in (raw or "").split(";"):
        item = item.strip()
        if not item:
            continue
        parts = item.split(":", 2)
        if len(parts) != 3:
            continue
        key_id, key_value, scope_blob = parts
        scopes = {scope.strip() for scope in scope_blob.split(",") if scope.strip()}
        if key_value:
            parsed[key_value] = KeyPolicy(key_id=key_id, key_value=key_value, scopes=scopes)
    return parsed


def _parse_csv_set(raw: str) -> Set[str]:
    return {item.strip().lower() for item in (raw or "").split(",") if item.strip()}


def _parse_bool(raw: str, default: bool) -> bool:
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    api_keys = _parse_api_keys(os.getenv("RAG_API_KEYS", ""))
    return Settings(
        backend_host=os.getenv("RAG_BACKEND_HOST", "0.0.0.0"),
        backend_port=int(os.getenv("RAG_BACKEND_PORT", "8000")),
        data_path=os.getenv("RAG_DATA_PATH", "./.rag/chroma"),
        collection_name=os.getenv("RAG_COLLECTION", "internal_full_repo"),
        source_file=os.getenv("RAG_SOURCE_FILE", "docs/skills/dio-process-skill.md"),
        source_dir=os.getenv("RAG_SOURCE_DIR", "../.."),
        source_mode=os.getenv("RAG_SOURCE_MODE", "repo").lower().strip(),
        chunk_size=int(os.getenv("RAG_CHUNK_SIZE", "1200")),
        chunk_overlap=int(os.getenv("RAG_CHUNK_OVERLAP", "200")),
        max_file_bytes=int(os.getenv("RAG_MAX_FILE_BYTES", "1500000")),
        exclude_dirs=_parse_csv_set(os.getenv("RAG_EXCLUDE_DIRS", ".git,.venv,.rag")),
        startup_reindex=_parse_bool(os.getenv("RAG_STARTUP_REINDEX"), False),
        api_keys=api_keys,
    )
