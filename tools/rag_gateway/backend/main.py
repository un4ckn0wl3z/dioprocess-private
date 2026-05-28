from __future__ import annotations

import hashlib
import json
import logging
import os
from pathlib import Path

from fastapi import Depends, FastAPI
from fastapi.middleware.cors import CORSMiddleware

from .auth import AuthContext, require_scope
from .config import get_settings
from .models import (
    Citation,
    CiteRequest,
    CiteResponse,
    HealthResponse,
    QueryRequest,
    QueryResponse,
    ReindexResponse,
    SectionsResponse,
    ChunkResult,
)
from .rag_store import RagStore


logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("rag_backend")

app = FastAPI(title="DioProcess Private RAG Backend", version="0.1.0")
settings = get_settings()
store = RagStore()

app.add_middleware(
    CORSMiddleware,
    allow_origins=[os.getenv("RAG_CORS_ALLOW_ORIGINS", "*")],
    allow_credentials=False,
    allow_methods=["POST", "GET"],
    allow_headers=["Authorization", "X-API-Key", "Content-Type"],
)


def _audit(event: str, actor: AuthContext, payload: dict) -> None:
    safe_payload = {
        "event": event,
        "actor": actor.key_id,
        "key_hash": actor.key_hash,
        **payload,
    }
    logger.info(json.dumps(safe_payload, ensure_ascii=True))


def _source_display() -> str:
    mode = settings.source_mode
    if mode == "repo":
        return settings.source_dir
    if mode == "file":
        return settings.source_file
    # auto mode prefers repo when present
    if Path(settings.source_dir).exists():
        return settings.source_dir
    return settings.source_file


def _source_exists() -> bool:
    mode = settings.source_mode
    if mode == "repo":
        return Path(settings.source_dir).is_dir()
    if mode == "file":
        return Path(settings.source_file).exists()
    return Path(settings.source_dir).is_dir() or Path(settings.source_file).exists()


@app.on_event("startup")
def startup() -> None:
    if not settings.startup_reindex:
        logger.info("startup_reindex_skipped source=%s", _source_display())
        return

    if _source_exists():
        try:
            count = store.reindex()
            logger.info("startup_reindex_success count=%s source=%s", count, _source_display())
        except Exception as exc:  # noqa: BLE001
            logger.exception("startup_reindex_failed: %s", exc)
    else:
        logger.warning("startup_source_missing source=%s", _source_display())


@app.post("/v1/rag/query", response_model=QueryResponse)
def query_rag(
    body: QueryRequest,
    auth: AuthContext = Depends(require_scope("query")),
) -> QueryResponse:
    query_hash = hashlib.sha256(body.query.encode("utf-8")).hexdigest()[:16]
    hits = store.query(body.query, body.top_k)
    _audit(
        "rag_query",
        auth,
        {"query_hash": query_hash, "top_k": body.top_k, "returned": len(hits)},
    )
    return QueryResponse(
        query=body.query,
        top_k=body.top_k,
        count=len(hits),
        chunks=[
            ChunkResult(
                chunk_id=h.chunk_id,
                score=h.score,
                text=h.text,
                source=h.source,
                section=h.section,
            )
            for h in hits
        ],
    )


@app.get("/v1/rag/sections", response_model=SectionsResponse)
def list_sections(
    auth: AuthContext = Depends(require_scope("sections")),
) -> SectionsResponse:
    sections = store.list_sections()
    _audit("rag_sections", auth, {"returned": len(sections)})
    return SectionsResponse(source=_source_display(), sections=sections)


@app.post("/v1/rag/cite", response_model=CiteResponse)
def cite_sources(
    body: CiteRequest,
    auth: AuthContext = Depends(require_scope("cite")),
) -> CiteResponse:
    citations = [Citation(**c) for c in store.citations(body.chunk_ids)]
    _audit("rag_cite", auth, {"requested": len(body.chunk_ids), "returned": len(citations)})
    return CiteResponse(citations=citations)


@app.post("/v1/admin/reindex", response_model=ReindexResponse)
def admin_reindex(
    auth: AuthContext = Depends(require_scope("admin:index")),
) -> ReindexResponse:
    count = store.reindex()
    _audit("admin_reindex", auth, {"indexed": count, "source": _source_display()})
    return ReindexResponse(indexed_chunks=count, source=_source_display())


@app.get("/v1/admin/health", response_model=HealthResponse)
def admin_health(
    auth: AuthContext = Depends(require_scope("admin:index")),
) -> HealthResponse:
    _audit("admin_health", auth, {})
    return HealthResponse(
        status="ok",
        collection=store.collection_name,
        source_exists=_source_exists(),
    )
