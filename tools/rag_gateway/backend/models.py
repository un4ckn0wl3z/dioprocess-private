from __future__ import annotations

from typing import List

from pydantic import BaseModel, Field


class QueryRequest(BaseModel):
    query: str = Field(min_length=1)
    top_k: int = Field(default=8, ge=1, le=50)


class ChunkResult(BaseModel):
    chunk_id: str
    score: float
    text: str
    source: str
    section: str


class QueryResponse(BaseModel):
    query: str
    top_k: int
    count: int
    chunks: List[ChunkResult]


class SectionsResponse(BaseModel):
    source: str
    sections: List[str]


class CiteRequest(BaseModel):
    chunk_ids: List[str] = Field(default_factory=list)


class Citation(BaseModel):
    chunk_id: str
    source: str
    section: str


class CiteResponse(BaseModel):
    citations: List[Citation]


class ReindexResponse(BaseModel):
    indexed_chunks: int
    source: str


class HealthResponse(BaseModel):
    status: str
    collection: str
    source_exists: bool
