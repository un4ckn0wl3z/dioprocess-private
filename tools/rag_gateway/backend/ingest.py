from __future__ import annotations

import hashlib
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable


HEADING_RE = re.compile(r"^(#{1,6})\s+(.+?)\s*$")


@dataclass
class Chunk:
    chunk_id: str
    text: str
    source: str
    section: str


def _normalize_line(line: str) -> str:
    return line.rstrip("\n")


def iter_sections(markdown: str) -> Iterable[tuple[str, str]]:
    current_heading = "Document Root"
    bucket: list[str] = []

    for raw_line in markdown.splitlines():
        line = _normalize_line(raw_line)
        m = HEADING_RE.match(line)
        if m:
            if bucket:
                yield current_heading, "\n".join(bucket).strip()
                bucket.clear()
            current_heading = m.group(2)
            bucket.append(line)
        else:
            bucket.append(line)

    if bucket:
        yield current_heading, "\n".join(bucket).strip()


def chunk_text(text: str, chunk_size: int, overlap: int) -> list[str]:
    text = text.strip()
    if not text:
        return []

    if len(text) <= chunk_size:
        return [text]

    chunks: list[str] = []
    start = 0
    step = max(1, chunk_size - overlap)
    while start < len(text):
        end = min(len(text), start + chunk_size)
        chunks.append(text[start:end].strip())
        if end >= len(text):
            break
        start += step
    return chunks


def _iter_repo_files(source_dir: Path, exclude_dirs: set[str]) -> Iterable[Path]:
    for root, dirs, files in os.walk(source_dir):
        dirs[:] = [d for d in dirs if d.lower() not in exclude_dirs]
        for filename in files:
            yield Path(root) / filename


def _is_text_blob(data: bytes) -> bool:
    if b"\x00" in data:
        return False
    try:
        data.decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def _read_text_file(path: Path, max_file_bytes: int) -> str | None:
    try:
        data = path.read_bytes()
    except OSError:
        return None

    if len(data) == 0 or len(data) > max_file_bytes:
        return None
    if not _is_text_blob(data):
        return None

    return data.decode("utf-8", errors="replace")


def _build_chunks_for_text(text: str, source_name: str, chunk_size: int, overlap: int) -> list[Chunk]:
    built: list[Chunk] = []
    is_markdown = source_name.lower().endswith((".md", ".markdown"))
    sections = list(iter_sections(text)) if is_markdown else [(source_name, text)]

    for section_index, (section, section_text) in enumerate(sections):
        for idx, piece in enumerate(chunk_text(section_text, chunk_size, overlap)):
            digest = hashlib.sha1(
                f"{source_name}:{section_index}:{section}:{idx}:{piece}".encode("utf-8")
            ).hexdigest()
            built.append(
                Chunk(
                    chunk_id=digest,
                    text=f"FILE: {source_name}\n{piece}",
                    source=source_name,
                    section=section,
                )
            )

    return built


def _build_from_single_file(source_file: str, chunk_size: int, overlap: int, max_file_bytes: int) -> list[Chunk]:
    path = Path(source_file)
    if not path.exists():
        raise FileNotFoundError(f"Source file not found: {source_file}")

    text = _read_text_file(path, max_file_bytes)
    if text is None:
        return []

    return _build_chunks_for_text(
        text=text,
        source_name=path.as_posix(),
        chunk_size=chunk_size,
        overlap=overlap,
    )


def _iter_from_single_file(source_file: str, chunk_size: int, overlap: int, max_file_bytes: int) -> Iterable[Chunk]:
    for chunk in _build_from_single_file(source_file, chunk_size, overlap, max_file_bytes):
        yield chunk


def _build_from_repo(
    source_dir: str,
    chunk_size: int,
    overlap: int,
    max_file_bytes: int,
    exclude_dirs: set[str],
) -> list[Chunk]:
    root = Path(source_dir).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    built: list[Chunk] = []
    for file_path in _iter_repo_files(root, exclude_dirs):
        text = _read_text_file(file_path, max_file_bytes)
        if text is None:
            continue

        rel_source = file_path.resolve().relative_to(root).as_posix()
        built.extend(
            _build_chunks_for_text(
                text=text,
                source_name=rel_source,
                chunk_size=chunk_size,
                overlap=overlap,
            )
        )

    return built


def _iter_from_repo(
    source_dir: str,
    chunk_size: int,
    overlap: int,
    max_file_bytes: int,
    exclude_dirs: set[str],
) -> Iterable[Chunk]:
    root = Path(source_dir).resolve()
    if not root.exists() or not root.is_dir():
        raise FileNotFoundError(f"Source directory not found: {source_dir}")

    for file_path in _iter_repo_files(root, exclude_dirs):
        text = _read_text_file(file_path, max_file_bytes)
        if text is None:
            continue

        rel_source = file_path.resolve().relative_to(root).as_posix()
        for chunk in _build_chunks_for_text(
            text=text,
            source_name=rel_source,
            chunk_size=chunk_size,
            overlap=overlap,
        ):
            yield chunk


def iter_chunks(
    source_file: str,
    source_dir: str,
    source_mode: str,
    chunk_size: int,
    overlap: int,
    max_file_bytes: int,
    exclude_dirs: set[str],
) -> Iterable[Chunk]:
    mode = (source_mode or "repo").lower().strip()
    if mode == "file":
        yield from _iter_from_single_file(source_file, chunk_size, overlap, max_file_bytes)
        return
    if mode == "repo":
        yield from _iter_from_repo(source_dir, chunk_size, overlap, max_file_bytes, exclude_dirs)
        return
    if mode == "auto":
        repo_root = Path(source_dir)
        if repo_root.exists() and repo_root.is_dir():
            yield from _iter_from_repo(source_dir, chunk_size, overlap, max_file_bytes, exclude_dirs)
            return
        yield from _iter_from_single_file(source_file, chunk_size, overlap, max_file_bytes)
        return

    raise ValueError("RAG_SOURCE_MODE must be one of: repo, file, auto")


def build_chunks(
    source_file: str,
    source_dir: str,
    source_mode: str,
    chunk_size: int,
    overlap: int,
    max_file_bytes: int,
    exclude_dirs: set[str],
) -> list[Chunk]:
    return list(
        iter_chunks(
            source_file=source_file,
            source_dir=source_dir,
            source_mode=source_mode,
            chunk_size=chunk_size,
            overlap=overlap,
            max_file_bytes=max_file_bytes,
            exclude_dirs=exclude_dirs,
        )
    )
