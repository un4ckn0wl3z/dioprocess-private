from __future__ import annotations

from dataclasses import dataclass
from itertools import islice

import chromadb
from chromadb.api.models.Collection import Collection
from chromadb.utils import embedding_functions

from .config import get_settings
from .ingest import Chunk, iter_chunks


@dataclass
class RetrievedChunk:
    chunk_id: str
    score: float
    text: str
    source: str
    section: str


class RagStore:
    def __init__(self) -> None:
        settings = get_settings()
        self._settings = settings
        self._client = chromadb.PersistentClient(path=settings.data_path)
        self._embedder = embedding_functions.DefaultEmbeddingFunction()
        self._collection: Collection = self._client.get_or_create_collection(
            name=settings.collection_name,
            embedding_function=self._embedder,
            metadata={"description": "DioProcess internal full skill store"},
        )

    @property
    def collection_name(self) -> str:
        return self._settings.collection_name

    def reindex(self) -> int:
        chunk_iter = iter_chunks(
            source_file=self._settings.source_file,
            source_dir=self._settings.source_dir,
            source_mode=self._settings.source_mode,
            chunk_size=self._settings.chunk_size,
            overlap=self._settings.chunk_overlap,
            max_file_bytes=self._settings.max_file_bytes,
            exclude_dirs=self._settings.exclude_dirs,
        )

        # Reset by recreating the collection to avoid backend-specific delete quirks.
        try:
            self._client.delete_collection(name=self._settings.collection_name)
        except Exception:  # noqa: BLE001
            pass

        self._collection = self._client.get_or_create_collection(
            name=self._settings.collection_name,
            embedding_function=self._embedder,
            metadata={"description": "DioProcess internal full skill store"},
        )

        indexed = 0
        while True:
            batch = list(islice(chunk_iter, 400))
            if not batch:
                break

            # Chroma rejects duplicate IDs in a single upsert call.
            dedup: dict[str, Chunk] = {c.chunk_id: c for c in batch}
            unique_chunks = list(dedup.values())
            if not unique_chunks:
                continue

            ids = [c.chunk_id for c in unique_chunks]
            docs = [c.text for c in unique_chunks]
            metadatas = [{"source": c.source, "section": c.section} for c in unique_chunks]

            self._collection.upsert(ids=ids, documents=docs, metadatas=metadatas)
            indexed += len(unique_chunks)

        return indexed

    def query(self, query_text: str, top_k: int) -> list[RetrievedChunk]:
        result = self._collection.query(
            query_texts=[query_text],
            n_results=top_k,
            include=["documents", "metadatas", "distances"],
        )

        ids = (result.get("ids") or [[]])[0]
        docs = (result.get("documents") or [[]])[0]
        metas = (result.get("metadatas") or [[]])[0]
        distances = (result.get("distances") or [[]])[0]

        out: list[RetrievedChunk] = []
        for i, chunk_id in enumerate(ids):
            metadata = metas[i] if i < len(metas) and metas[i] else {}
            distance = float(distances[i]) if i < len(distances) and distances[i] is not None else 0.0
            score = 1.0 / (1.0 + max(0.0, distance))
            out.append(
                RetrievedChunk(
                    chunk_id=chunk_id,
                    score=score,
                    text=docs[i] if i < len(docs) else "",
                    source=str(metadata.get("source", "unknown")),
                    section=str(metadata.get("section", "Document Root")),
                )
            )
        return out

    def list_sections(self) -> list[str]:
        all_data = self._collection.get(include=["metadatas"])
        sections: set[str] = set()
        for m in all_data.get("metadatas") or []:
            if not m:
                continue
            section = str(m.get("section", "")).strip()
            if section:
                sections.add(section)
        return sorted(sections)

    def citations(self, chunk_ids: list[str]) -> list[dict[str, str]]:
        if not chunk_ids:
            return []
        got = self._collection.get(ids=chunk_ids, include=["metadatas"])
        ids = got.get("ids") or []
        metas = got.get("metadatas") or []
        citations: list[dict[str, str]] = []
        for i, cid in enumerate(ids):
            meta = metas[i] if i < len(metas) and metas[i] else {}
            citations.append(
                {
                    "chunk_id": cid,
                    "source": str(meta.get("source", "unknown")),
                    "section": str(meta.get("section", "Document Root")),
                }
            )
        return citations
