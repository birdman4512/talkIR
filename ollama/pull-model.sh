#!/bin/sh
# Waits for the Ollama daemon to become ready, then pulls the configured model.
# OLLAMA_MODEL env var is set by docker-compose (default: llama3.2:3b).

MODEL="${OLLAMA_MODEL:-llama3.2:3b}"

echo "==> Waiting for Ollama daemon..."
until curl -sf http://localhost:11434/api/version > /dev/null 2>&1; do
    sleep 2
done

echo "==> Pulling model: ${MODEL}"
ollama pull "${MODEL}"
echo "==> Model ready: ${MODEL}"
