FROM ollama/ollama:0.18.3

COPY pull-model.sh /pull-model.sh
RUN chmod +x /pull-model.sh

# Start the server, download the model on first run, then keep serving.
# SERVER_PID ensures `wait` blocks on the ollama process specifically —
# the container stays alive regardless of whether the model pull succeeded.
ENTRYPOINT ["/bin/sh", "-c", "ollama serve & SERVER_PID=$!; /pull-model.sh; wait $SERVER_PID"]
