#!/bin/bash
###############################################################################
# Ollama Entrypoint Script
# 
# Starts the Ollama server and automatically pulls the llama3:8b model
# if it's not already available locally.
###############################################################################

set -e

echo "=========================================="
echo " AegisTrap - Ollama LLM Service"
echo "=========================================="
echo ""

# Start Ollama server in the background
echo "[*] Starting Ollama server..."
ollama serve &
OLLAMA_PID=$!

# Wait for Ollama to be ready
echo "[*] Waiting for Ollama to initialize..."
MAX_RETRIES=30
RETRY_COUNT=0
until curl -sf http://localhost:11434/api/tags > /dev/null 2>&1; do
    RETRY_COUNT=$((RETRY_COUNT + 1))
    if [ $RETRY_COUNT -ge $MAX_RETRIES ]; then
        echo "[!] ERROR: Ollama failed to start after ${MAX_RETRIES} attempts"
        exit 1
    fi
    echo "    Waiting... (attempt ${RETRY_COUNT}/${MAX_RETRIES})"
    sleep 2
done

echo "[+] Ollama server is ready!"
echo ""

# Check if llama3:8b model is already available
echo "[*] Checking for llama3:8b model..."
if ollama list | grep -q "llama3:8b"; then
    echo "[+] Model llama3:8b is already available."
else
    echo "[*] Downloading llama3:8b model (this may take a while on first run)..."
    echo "    Model size: ~4.7GB"
    echo ""
    ollama pull llama3:8b
    echo ""
    echo "[+] Model llama3:8b downloaded successfully!"
fi

echo ""
echo "=========================================="
echo " Ollama ready - Model: llama3:8b"
echo " API endpoint: http://0.0.0.0:11434"
echo "=========================================="
echo ""

# Keep the Ollama server running in the foreground
wait $OLLAMA_PID
