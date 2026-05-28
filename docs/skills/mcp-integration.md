# DioProcess RAG MCP Integration

This guide shows how to consume the private RAG via MCP tools.

## MCP tools exposed

- retrieve_internal_skill
- list_skill_sections
- cite_sources

## Local stdio configuration example

Use this MCP server command in your client config:

- command: python
- args:
  - -m
  - mcp_server.server
- env:
  - MCP_TRANSPORT=stdio
  - RAG_BACKEND_URL=localhost backend endpoint on port 8000
  - RAG_MCP_SERVICE_KEY=<mcp_service_key>

## Remote HTTP/SSE deployment

- Run gateway stack from tools/rag_gateway.
- MCP endpoint is proxied at `/mcp/*`.
- Protect the host with network ACL and TLS.

## Access model

- End users never receive vector DB access.
- MCP server never queries vector DB directly.
- Backend validates key scopes before retrieval.

## Recommended key split

- admin key: index/health + read
- client read key: query/sections/cite
- mcp service key: query/sections/cite only
