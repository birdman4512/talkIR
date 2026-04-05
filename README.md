# TalkIR — Security Log Intelligence

Chat with your logs using a local or cloud LLM. Drop JSON log files into `./logs/`, select indices in the sidebar, and ask questions in plain English. TalkIR translates your question into an Elasticsearch query, fetches the relevant events, and streams an analysis back — with optional threat intelligence enrichment for any IP addresses found.

---

## Features

- **Smart query generation** — LLM generates Elasticsearch Query DSL from plain English, using your actual index field names and types. Falls back to keyword search if the LLM fails.
- **Streaming responses** — results and LLM analysis stream token-by-token via SSE; no waiting for the full response.
- **Thinking models** — DeepSeek R1 and similar models show their reasoning chain in a collapsible block before answering.
- **Aggregations** — supports `terms`, `composite`, nested, and date histogram aggregations; results are flattened into readable tables.
- **Threat intelligence** — optionally enriches IP addresses found in results via AbuseIPDB and/or VirusTotal.
- **Personas** — switch between Cybersecurity Analyst, Data Analyst, DevOps/SRE, and General Assistant system prompts.
- **Cloud LLM support** — route queries to Claude (Anthropic) or OpenAI instead of a local model.
- **Model catalogue** — browse, download, and delete Ollama models from within the UI; sortable by RAM, speed, or name.
- **Conversation history** — the last 20 turns are included as context so follow-up questions work naturally.

---

## Architecture

```
./logs/*.json  ──►  Fluent Bit  ──►  Elasticsearch (single-node, HTTPS)
                                              │
                                         Kibana :5601
                                              │
                    Browser :3000  ◄──  nginx / frontend
                                              │
                                          FastAPI :8000
                                         /          \
                                    Ollama         Claude / OpenAI
                                  (local LLM)     (cloud LLM, optional)
```

| Service       | Purpose                              | Default port    |
|---------------|--------------------------------------|-----------------|
| elasticsearch | Single-node ES with TLS              | 9200            |
| kibana        | Log visualisation dashboard          | 5601            |
| fluent-bit    | JSON log ingestion from `./logs/`    | —               |
| ollama        | Local LLM inference (CPU or GPU)     | 11434           |
| api           | Chat / search backend (FastAPI)      | 8000 (internal) |
| frontend      | Chat UI served by nginx              | 3000            |

---

## Prerequisites

- Docker ≥ 24 and Docker Compose ≥ 2.20
- 5 GB RAM free for `qwen2.5:7b` (the default model); 2 GB for the `llama3.2:3b` fallback
- ~2–5 GB disk for model weights (downloaded on first start)

### Linux only — increase `vm.max_map_count`

Elasticsearch requires this kernel parameter. Without it the ES node will crash at startup.

```bash
sudo sysctl -w vm.max_map_count=262144
# Persist across reboots:
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

## Quick start

### 1. Clone and configure

```bash
git clone https://github.com/birdman4512/talkIR.git
cd talkIR
cp .env.example .env
```

Generate credentials and write them into `.env`:

```bash
ELASTIC_PASS=$(openssl rand -hex 20)
KIBANA_PASS=$(openssl rand -hex 20)
KIBANA_KEY=$(openssl rand -hex 32)
JWT_SECRET=$(openssl rand -hex 32)

sed -i "s/^ELASTIC_PASSWORD=.*/ELASTIC_PASSWORD=${ELASTIC_PASS}/"     .env
sed -i "s/^KIBANA_PASSWORD=.*/KIBANA_PASSWORD=${KIBANA_PASS}/"         .env
sed -i "s/^KIBANA_ENCRYPTION_KEY=.*/KIBANA_ENCRYPTION_KEY=${KIBANA_KEY}/" .env
sed -i "s/^JWT_SECRET=.*/JWT_SECRET=${JWT_SECRET}/"                    .env
```

> **macOS**: add `''` after `-i` in each `sed` command.

### 2. Start the stack

```bash
docker compose up -d
```

First run takes **3–5 minutes** while the LLM downloads. Watch progress:

```bash
docker compose logs -f api   # ready when: "Application startup complete."
```

### 3. Open the UI

```
http://localhost:3000
```

Kibana is at `http://localhost:5601` — log in with `elastic` / your `ELASTIC_PASSWORD`.

### 4. Drop in a log file

```bash
cp /path/to/your/events.json ./logs/
```

Fluent Bit picks it up within ~10 seconds. Refresh the index list in the sidebar and start asking questions.

---

## Log file format

Each line must be a valid JSON object (NDJSON):

```json
{"timestamp":"2024-01-15T08:23:11Z","event_type":"login_failure","src_ip":"203.0.113.5","user":"admin"}
{"timestamp":"2024-01-15T08:23:12Z","event_type":"login_success","src_ip":"198.51.100.2","user":"jsmith"}
```

The index name is derived from the filename:
- `./logs/auth_events.json` → index `auth_events-YYYY.MM.DD`
- `./logs/firewall.json` → index `firewall-YYYY.MM.DD`

---

## Configuration

All settings live in `.env`. Key variables:

| Variable | Purpose | Default |
|---|---|---|
| `ELASTIC_PASSWORD` | Elasticsearch `elastic` user password | — (required) |
| `KIBANA_PASSWORD` | Kibana system password | — (required) |
| `KIBANA_ENCRYPTION_KEY` | Saved-object encryption (32+ chars) | — (required) |
| `JWT_SECRET` | Session token signing key (32+ chars) | — (required) |
| `OLLAMA_MODEL` | Default Ollama model | `qwen2.5:7b` |
| `ANTHROPIC_API_KEY` | Enables Claude as a provider | — (optional) |
| `OPENAI_API_KEY` | Enables OpenAI as a provider | — (optional) |
| `ABUSEIPDB_API_KEY` | IP threat intel (free: 1k/day) | — (optional) |
| `VIRUSTOTAL_API_KEY` | IP threat intel (free: 500/day) | — (optional) |
| `MEM_LIMIT` | Per-ES-node memory limit (bytes) | `1073741824` (1 GB) |

---

## Choosing a model

Open **[ cfg ]** in the sidebar to browse the model catalogue. Models can be downloaded and deleted from within the UI.

| Model | RAM | Speed | Notes |
|---|---|---|---|
| `llama3.2:1b` | 1.3 GB | Fast | Minimal footprint — quick triage |
| `deepseek-r1:1.5b` | 1.1 GB | Fast | Thinking model — shows reasoning, low RAM |
| `llama3.2:3b` | 2.0 GB | Fast | **Best default** — fast, reliable query generation |
| `qwen2.5:7b` | 4.4 GB | Medium | Best for tables, counts, aggregation queries |
| `llama3.1:8b` | 4.9 GB | Medium | Strong multi-step reasoning |
| `deepseek-r1:7b` | 4.7 GB | Slow | Full thinking model — step-by-step reasoning |
| `deepseek-r1:8b` | 4.9 GB | Slow | Best reasoning quality for complex investigations |

For fast responses without local RAM requirements, switch the **provider** dropdown to `claude` or `openai` and enter your API key in `.env`.

---

## Personas

Use the **// persona** dropdown in the sidebar to change how the LLM frames its analysis:

| Persona | Best for |
|---|---|
| Cybersecurity Analyst | SIEM logs, threat hunting, MITRE ATT&CK mapping |
| Data Analyst | General pattern analysis, trends, anomalies |
| DevOps / SRE | Application logs, error rates, service health |
| General Assistant | Any structured data |

---

## Threat intelligence

Enable the **threat intel** checkbox before sending a query. TalkIR will:

1. Extract unique public IP addresses from the ES results
2. Look them up concurrently against AbuseIPDB and/or VirusTotal (whichever keys are configured)
3. Stream enrichment results into the UI (colour-coded by risk)
4. Include the enrichment data in the LLM prompt so the analysis can reference it

Configure API keys in `.env`. Both services offer free tiers (AbuseIPDB: 1,000 lookups/day; VirusTotal: 500/day).

---

## GPU acceleration (NVIDIA)

1. Install the [NVIDIA Container Toolkit](https://docs.nvidia.com/datacenter/cloud-native/container-toolkit/install-guide.html)
2. Uncomment the `deploy:` block in `docker-compose.yml` under the `ollama` service
3. Restart: `docker compose up -d ollama`

---

## Development

```bash
# Run API unit tests (no Docker required — ES and Ollama are mocked)
cd api
pip install -r requirements-dev.txt
pytest tests/ -v

# Run with coverage
pytest tests/ --cov=app --cov-report=term-missing

# Rebuild one service after a code change
docker compose build api && docker compose up -d --no-deps api
# Then restart frontend so nginx re-resolves the API hostname:
docker compose restart frontend

# Tail logs
docker compose logs -f api
docker compose logs -f fluent-bit

# Validate the compose file
docker compose config --quiet

# Check Lua syntax
luac5.4 -p fluent-bit/extract_index.lua

# Full reset (destroys all ES data and model cache)
docker compose down -v
```

### File map for common tasks

| Task | File |
|---|---|
| Change the system prompt for a persona | `api/app/routes/chat.py` → `PERSONAS` dict |
| Add a new persona | `api/app/routes/chat.py` → `PERSONAS` + `frontend/html/index.html` |
| Change the ES query generation prompt | `api/app/routes/chat.py` → `QUERY_GEN_PROMPT` |
| Add a model to the catalogue | `api/app/routes/models.py` → `CATALOGUE` |
| Change how filenames map to index names | `fluent-bit/extract_index.lua` |
| Add an nginx route | `frontend/nginx.conf` |
| Add a CI job | `.github/workflows/ci.yml` |

---

## Troubleshooting

**ES won't start (exit code 78 / "max virtual memory areas")**
→ Run `sudo sysctl -w vm.max_map_count=262144` (Linux only)

**`setup` container keeps restarting**
→ Check credentials are set: `grep PASSWORD .env`

**"Kibana server is not ready yet" for several minutes**
→ Normal on first start — Kibana waits for `setup` to set the `kibana_system` password. Check: `docker compose logs setup`

**Login returns 502 after restarting the API**
→ The API got a new Docker IP and nginx cached the old one. Fix: `docker compose restart frontend`

**OOM error when running a query**
→ Switch to a `low mem` model (`llama3.2:1b` or `deepseek-r1:1.5b`) or reduce the results slider. Close other applications to free RAM.

**"does not support thinking" error**
→ The selected model doesn't support the thinking API. Thinking mode is only sent to DeepSeek R1, QwQ, and similar models — switch models or this is already handled automatically.

**Indices don't appear after dropping a log file**
→ Check `docker compose logs fluent-bit`. Each line of the file must be a valid JSON object (not a JSON array).

**Query fell back to keyword search**
→ The LLM failed to produce valid Elasticsearch JSON. Check the "ES query" block in the UI to see what was generated. Try a different model or rephrase the question.

---

## CI/CD

GitHub Actions runs on every push and PR to `main`:

1. **Lint Dockerfiles** — hadolint
2. **Validate compose** — `docker compose config`
3. **API unit tests** — pytest with mocked ES + Ollama
4. **Lua syntax check** — luac
5. **Container scanning** — Trivy (CRITICAL/HIGH CVEs)
6. **Secret scanning** — gitleaks
