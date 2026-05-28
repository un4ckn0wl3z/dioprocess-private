# DioProcess Private RAG Gateway

This service provides a private RAG backend plus a thin MCP adapter.

Architecture:

- FastAPI backend indexes and queries the full repository text/code by default.
- Chroma persistent local vector store.
- MCP server exposes tools and calls backend only.
- Reverse proxy exposes REST and MCP HTTP/SSE endpoints.

## 1) Quick start (Docker on local machine)

1. Copy environment file:

```powershell
Copy-Item .env.example .env
```

1. Set real keys in `.env` for `RAG_API_KEYS` and `RAG_MCP_SERVICE_KEY`.
1. From `tools/rag_gateway` run:

```powershell
docker compose up --build
```

Exposed endpoint via proxy:

- REST: [http://localhost:8080/v1/*](http://localhost:8080/v1/)
- MCP HTTP/SSE pass-through: [http://localhost:8080/mcp/*](http://localhost:8080/mcp/)

## 2) Quick start (native local, no Docker)

From `tools/rag_gateway`:

1. Create and activate a virtual env (PowerShell):

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
```

1. Install dependencies:

```powershell
python -m pip install -r requirements.txt
```

1. Copy env file and set keys:

```powershell
Copy-Item .env.example .env
```

Set `RAG_API_KEYS` and `RAG_MCP_SERVICE_KEY` in `.env`.

1. Start backend (terminal 1):

```powershell
python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
```

1. Start MCP in stdio mode (terminal 2, local client launches this too):

```powershell
$env:MCP_TRANSPORT = "stdio"
python -m mcp_server.server
```

Optional SSE mode (if you want browser/HTTP-style MCP):

```powershell
$env:MCP_TRANSPORT = "sse"
$env:MCP_HOST = "127.0.0.1"
$env:MCP_PORT = "9000"
python -m mcp_server.server
```

Native local endpoints:

- Backend REST: [http://127.0.0.1:8000/v1/*](http://127.0.0.1:8000/v1/)
- MCP SSE (optional): [http://127.0.0.1:9000/sse](http://127.0.0.1:9000/sse)

## 3) API auth

Send either:

- `Authorization: Bearer <key>`
- `X-API-Key: <key>`

Scopes:

- query
- sections
- cite
- admin:index

## 4) REST endpoints

- POST /v1/rag/query
  - body: { "query": "...", "top_k": 8 }
- GET /v1/rag/sections
- POST /v1/rag/cite
  - body: { "chunk_ids": ["..."] }
- POST /v1/admin/reindex (admin:index only)
- GET /v1/admin/health (admin:index only)

## 5) MCP tools

- retrieve_internal_skill(query, top_k)
- list_skill_sections()
- cite_sources(chunk_ids)

The MCP adapter does not access Chroma directly. It only calls the backend.

## 6) Running MCP server for stdio clients

For local Claude/Copilot style clients, run:

- set MCP_TRANSPORT=stdio
- python -m mcp_server.server

Example client configs are provided:

- tools/rag_gateway/examples/mcp.local.stdio.json
- tools/rag_gateway/examples/mcp.local.sse.json

You can copy one into your VS Code user MCP config and adjust the keys/paths.

## 7) Security notes

- Do not expose Chroma storage directory.
- Keep proxy and backend private or IP-restricted.
- Rotate API keys regularly.
- Keep audit logs for queries and admin operations.
- Index only approved documents.

## 8) Source indexed by default

- Full repository from `RAG_SOURCE_DIR` (default mode is `RAG_SOURCE_MODE=repo`).

Source controls:

- `RAG_SOURCE_MODE=repo|file|auto`
- `RAG_SOURCE_DIR` for recursive repo indexing
- `RAG_SOURCE_FILE` for single-file indexing
- `RAG_EXCLUDE_DIRS` for folders to skip
- `RAG_MAX_FILE_BYTES` to skip very large files
- `RAG_STARTUP_REINDEX=0|1` to control indexing at backend startup (default `0`)

For large repositories, keep startup reindex disabled and run manual reindex via:

- `POST /v1/admin/reindex`
