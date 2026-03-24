# TalkIR — Security Log Intelligence

Chat with your security logs using a local LLM. Drop JSON log files into `./logs/`, select indices in the UI, and ask questions in plain English.

## Architecture

```
./logs/*.json  ──►  Fluent Bit  ──►  Elasticsearch (single-node TLS)
                                              │
                                         Kibana :5601
                                              │
                    Browser :3000  ◄──  nginx / frontend
                                              │
                                          FastAPI
                                              │
                                          Ollama (LLM)
```

| Service       | Purpose                          | Default port    |
|---------------|----------------------------------|-----------------|
| elasticsearch | Single-node ES (HTTPS/mTLS)      | 9200            |
| Kibana        | Log visualisation                | 5601            |
| Fluent Bit    | JSON log ingestion               | —               |
| Ollama        | Local LLM inference (CPU)        | 11434           |
| API           | Chat / search backend            | 8000 (internal) |
| Frontend      | Chat UI                          | 3000            |

---

## Prerequisites

- Docker ≥ 24 and Docker Compose ≥ 2.20
- 8 GB RAM minimum (16 GB recommended for a 7B model)
- ~4 GB disk for `llama3.2:3b` model weights (downloaded on first start)

### Linux only — increase vm.max_map_count

Elasticsearch requires this kernel parameter. Without it, the ES nodes will crash on startup.

```bash
sudo sysctl -w vm.max_map_count=262144
```

To persist it across reboots:

```bash
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
```

---

## Setup

### 1. Clone the repository

```bash
git clone https://github.com/your-org/talkir.git
cd talkir
```

### 2. Create and configure the environment file

Copy the example file:

```bash
cp .env.example .env
```

Generate random credentials and write them into `.env` in one step:

```bash
# Generate cryptographically random values (hex — safe for sed and shell quoting)
ELASTIC_PASS=$(openssl rand -hex 20)
KIBANA_PASS=$(openssl rand -hex 20)
KIBANA_KEY=$(openssl rand -hex 32)   # 64 chars — satisfies the 32+ char requirement

sed -i "s/^ELASTIC_PASSWORD=.*/ELASTIC_PASSWORD=${ELASTIC_PASS}/" .env
sed -i "s/^KIBANA_PASSWORD=.*/KIBANA_PASSWORD=${KIBANA_PASS}/" .env
sed -i "s/^KIBANA_ENCRYPTION_KEY=.*/KIBANA_ENCRYPTION_KEY=${KIBANA_KEY}/" .env
```

> **macOS** — `sed -i` requires an empty backup extension argument:
> ```bash
> sed -i '' "s/^ELASTIC_PASSWORD=.*/ELASTIC_PASSWORD=${ELASTIC_PASS}/" .env
> sed -i '' "s/^KIBANA_PASSWORD=.*/KIBANA_PASSWORD=${KIBANA_PASS}/" .env
> sed -i '' "s/^KIBANA_ENCRYPTION_KEY=.*/KIBANA_ENCRYPTION_KEY=${KIBANA_KEY}/" .env
> ```

Verify the result and save the passwords somewhere safe before continuing:

```bash
grep -E 'PASSWORD|ENCRYPTION_KEY' .env
```

To change the LLM model (optional — see [Changing the LLM model](#changing-the-llm-model)):

```bash
sed -i "s/^OLLAMA_MODEL=.*/OLLAMA_MODEL=mistral:7b-instruct/" .env
```

### 3. Start the stack

```bash
docker compose up -d
```

On first run this will:
1. Build the custom images (Fluent Bit, Ollama, API, frontend)
2. Generate TLS certificates
3. Start Elasticsearch
4. Start Kibana, Fluent Bit, and the chat API
5. Download the LLM model weights into the `ollama_data` volume (~2–4 GB)

### 4. Wait for the stack to become ready

The first run takes **3–5 minutes** while the LLM model downloads. Watch the API logs — it won't start until Elasticsearch and Ollama are both healthy:

```bash
docker compose logs -f api
# Ready when you see: "Application startup complete."
```

You can also check the status of all services:

```bash
docker compose ps
```

All services should show `healthy` or `running`. If a service shows `starting`, give it more time.

### 5. Open the chat UI

```
http://localhost:3000
```

Kibana is available at `http://localhost:5601` (login: `elastic` / your `ELASTIC_PASSWORD`).

### 6. Ingest your first log file

Drop any newline-delimited JSON file into `./logs/`. Fluent Bit picks it up within ~10 seconds:

```bash
# The sample file included in the repo is already there:
ls logs/sample_auth.json

# Or copy your own:
cp /path/to/your/firewall_events.json ./logs/
```

The Elasticsearch index name is derived from the filename:
- `./logs/sample_auth.json` → index `sample_auth-YYYY.MM.DD`
- `./logs/firewall_events.json` → index `firewall_events-YYYY.MM.DD`

Refresh the index list in the UI sidebar and start asking questions.

---

## Log file format

Each line must be a valid JSON object (newline-delimited JSON / NDJSON):

```json
{"timestamp":"2024-01-15T08:23:11Z","event_type":"login_failure","src_ip":"10.0.0.1","user":"admin"}
{"timestamp":"2024-01-15T08:23:12Z","event_type":"login_success","src_ip":"10.0.0.2","user":"jsmith"}
```

---

## Accessing services

| Service       | URL                          | Credentials                   |
|---------------|------------------------------|-------------------------------|
| Chat UI       | http://localhost:3000        | —                             |
| Kibana        | http://localhost:5601        | `elastic` / `ELASTIC_PASSWORD`|
| Elasticsearch | https://localhost:9200       | `elastic` / `ELASTIC_PASSWORD`|
| Ollama API    | http://localhost:11434       | —                             |

To test the Elasticsearch connection directly (requires `curl` and the CA cert from the running container):

```bash
docker compose cp setup:/usr/share/elasticsearch/config/certs/ca/ca.crt /tmp/ca.crt
curl --cacert /tmp/ca.crt -u elastic:YourStrongPassword1! https://localhost:9200
```

---

## Changing the LLM model

Edit `.env` and restart:

```bash
# Switch to a higher-quality model (requires more RAM and is slower on CPU)
sed -i 's/^OLLAMA_MODEL=.*/OLLAMA_MODEL=mistral:7b-instruct/' .env

docker compose up -d ollama api
docker compose logs -f ollama  # watch the new model download
```

Available CPU-friendly options:

| Model                  | Size   | Speed  | Quality   |
|------------------------|--------|--------|-----------|
| `llama3.2:3b` (default)| ~2 GB  | Fast   | Good      |
| `phi3.5:mini`          | ~2 GB  | Fastest| Good      |
| `mistral:7b-instruct`  | ~4 GB  | Slower | Very good |

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

# Run tests with coverage report
pytest tests/ --cov=app --cov-report=term-missing

# Rebuild and restart a single service after code changes
docker compose build api && docker compose up -d api

# Tail logs for a specific service
docker compose logs -f fluent-bit

# Reset everything and start clean (destroys all ES data and model cache)
docker compose down -v
```

---

## Troubleshooting

**ES nodes won't start (exit code 78 or "max virtual memory areas" error)**
→ Run `sudo sysctl -w vm.max_map_count=262144` (Linux only)

**`setup` container keeps restarting**
→ Check that `ELASTIC_PASSWORD` and `KIBANA_PASSWORD` are set in `.env`:
```bash
grep PASSWORD .env
```

**Kibana shows "Kibana server is not ready yet" for several minutes**
→ Normal on first start. Kibana waits for the `setup` container to set the `kibana_system` password. Check: `docker compose logs setup`

**Model badge shows "model: …" (never updates)**
→ Ollama is still downloading the model. Check: `docker compose logs ollama`

**Indices don't appear after dropping a log file**
→ Check Fluent Bit logs: `docker compose logs fluent-bit`. Confirm each line of the file is a valid JSON object (not a JSON array).

---

## CI/CD

GitHub Actions runs on every push and PR to `main`:

1. **Lint Dockerfiles** — hadolint
2. **Validate compose** — `docker compose config`
3. **API unit tests** — pytest with mocked ES + Ollama
4. **Lua syntax check** — luac
5. **Container scanning** — Trivy (CRITICAL/HIGH CVEs)
6. **Secret scanning** — gitleaks
