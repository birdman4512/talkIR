# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Commands

```bash
# Start the full stack (first run downloads the LLM — allow 3–5 min)
docker compose up -d

# Run API unit tests (no Docker needed — ES and Ollama are fully mocked)
cd api && pip install -r requirements-dev.txt && pytest tests/ -v

# Run tests with coverage
cd api && pytest tests/ --cov=app --cov-report=term-missing

# Rebuild a single service after code changes
docker compose build api && docker compose up -d api

# Tail logs for a service
docker compose logs -f fluent-bit

# Validate the compose file
docker compose config --quiet

# Check Lua syntax
luac5.4 -p fluent-bit/extract_index.lua

# Tear down everything including volumes (destroys all ES data)
docker compose down -v
```

## Networks

Two Docker networks are used to isolate traffic:

- **`internal`** (`internal: true`) — no external routing; all service-to-service communication. Containers here cannot reach the internet.
- **`public`** — standard bridge with internet access via Docker NAT; used only by services that need host port bindings or internet access.

| Service | Networks | Reason |
|---------|----------|--------|
| setup | internal | reaches elasticsearch, no internet needed |
| elasticsearch | internal + public | reaches kibana/api/fluent-bit + host port 9200 |
| kibana | internal + public | reaches ES + host port 5601 |
| fluent-bit | internal | reaches ES only |
| ollama | internal + public | reachable by api + internet for model pull |
| api | internal | reaches ES + ollama, proxied by frontend |
| frontend | internal + public | reaches api + host port 3000 |

## Architecture

The stack has six layers that talk to each other over the `internal` Docker network:

1. **TLS setup container** (`setup` service) — runs once using the ES image to invoke `elasticsearch-certutil`. Generates a CA and per-node certificates (for `elasticsearch` and `kibana`) into the shared `certs` volume, then waits for `elasticsearch` and sets the `kibana_system` password. Health check passes when `certs.zip` exists.

2. **Elasticsearch** (`elasticsearch`) — single-node, `discovery.type=single-node` (skips cluster bootstrap). Security is enabled by default in ES 8.x. TLS is configured for both HTTP (port 9200) and transport layers using environment variables — no separate `elasticsearch.yml` file. Port 9200 is bound to the host.

3. **Kibana** (`kibana`) — connects to `elasticsearch` via HTTPS using mutual TLS. Kibana presents `config/certs/kibana/kibana.crt` as its client certificate (`ELASTICSEARCH_SSL_CERTIFICATE` + `ELASTICSEARCH_SSL_KEY` env vars). ES is set to `client_authentication=optional` so it verifies Kibana's certificate when presented, while still allowing basic-auth-only clients (Fluent Bit, API). Three encryption keys must all be set to the same 32+ char value (`KIBANA_ENCRYPTION_KEY`) to ensure saved objects survive restarts.

4. **Fluent Bit** (`fluent-bit`) — tails `./logs/*.json` (bind-mounted from the host). The `extract_index.lua` script reads the `filename` field injected by `Path_Key`, strips the directory and `.json` extension, and writes the result to `record["log_index"]`. The ES output uses `Logstash_Prefix_Key log_index` to create dated indices like `auth-2024.01.15`.

5. **Ollama** (`ollama`) — CPU-only by default; GPU can be enabled by uncommenting the `deploy:` block. Uses the base `ollama/ollama:latest` image directly. A separate `ollama-pull` one-shot service pulls the model after `ollama` is healthy; `api` waits for `ollama-pull` to complete. `OLLAMA_MODEL` env var controls which model is used.

6. **FastAPI** (`api`) — the intelligence layer. `POST /api/chat` searches ES with `multi_match` across selected indices, formats the top N hits as context, appends the user's question, and streams the Ollama response via SSE (`text/event-stream`). The system prompt is defined in `api/app/routes/chat.py`. `GET /api/indices` lists user-visible (non-dot-prefixed) indices.

7. **Frontend** (`frontend`) — static HTML/CSS/JS served by nginx. nginx proxies `/api/` to the FastAPI container with `proxy_buffering off` on `/api/chat` so SSE streams through without buffering.

## Key design decisions

- **Single-node ES with `discovery.type=single-node`**: Eliminates cluster bootstrap/quorum complexity. No `cluster.initial_master_nodes` or `discovery.seed_hosts` needed.
- **mTLS Kibana↔ES vs basic-auth-only other clients**: `client_authentication=optional` (not `required`) is intentional. It lets Kibana authenticate via certificate while Fluent Bit and the API continue using basic auth over TLS without needing their own client certs. Changing to `required` would mean generating and configuring client certs for every service.
- **`internal: true` network isolation**: The `internal` Docker network has no gateway route, so containers on it cannot make outbound internet calls. Ollama and elasticsearch are also on `public` for internet access (model downloads) and host port bindings respectively. The API has no host port — it is only reachable through the nginx frontend.
- **Dynamic index names**: Fluent Bit uses a Lua filter (not `Rewrite_Tag`) because `Logstash_Prefix_Key` needs the value in the record, and a Lua function is the cleanest way to transform a filesystem path into a clean index name.
- **SSE via `fetch` not `EventSource`**: The chat endpoint is `POST` (needs a JSON body with query + selected indices). `EventSource` only supports GET, so the frontend uses `fetch` + `ReadableStream`.
- **Unit tests mock ES and Ollama**: All test fixtures in `api/tests/conftest.py` use `AsyncMock` against the module-level ES singleton in `es_client.py`.
- **`X-Accel-Buffering: no` header**: Set on SSE responses in `chat.py` to instruct nginx (via `proxy_hide_header` / passthrough) not to buffer the stream.

## Environment variables

All configuration is in `.env` (copy from `.env.example`). The three passwords (`ELASTIC_PASSWORD`, `KIBANA_PASSWORD`, `KIBANA_ENCRYPTION_KEY`) must be changed before first run. `OLLAMA_MODEL` controls the LLM; `ES_MEM_LIMIT` and `KIBANA_MEM_LIMIT` control per-container memory limits (bytes).

## File map for common tasks

| Task | Files |
|------|-------|
| Change the cybersecurity system prompt | `api/app/routes/chat.py` — `SYSTEM_PROMPT` constant |
| Add a new API endpoint | `api/app/routes/` + register router in `api/app/main.py` |
| Change how filenames map to index names | `fluent-bit/extract_index.lua` |
| Change the ES search query | `api/app/routes/chat.py` — `_search_context()` |
| Change frontend UI | `frontend/html/` |
| Add nginx routes | `frontend/nginx.conf` |
| Add a CI job | `.github/workflows/ci.yml` |
