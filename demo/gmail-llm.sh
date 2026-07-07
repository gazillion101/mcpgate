#!/usr/bin/env bash
# The REAL demo: a genuine LLM triaging a Gmail-shaped inbox that contains one
# prompt-injection email. Same model, same inbox — first without the gateway
# (the model gets hijacked and forwards/deletes for real), then through it
# (both actions denied at the gate).
#
# Needs an OpenAI-compatible endpoint at MCPGATE_LLM_BASE:
#   - Ollama locally (default), or
#   - a LiteLLM proxy fanning out to Claude / DeepSeek / Gemini / OpenAI.
# Swap providers with MCPGATE_LLM_MODEL / MCPGATE_LLM_BASE — no code change.
set -euo pipefail
cd "$(dirname "$0")/.."

export MCPGATE_LLM_MODEL="${MCPGATE_LLM_MODEL:-qwen2.5:14b-instruct}"
export MCPGATE_LLM_BASE="${MCPGATE_LLM_BASE:-http://127.0.0.1:11434/v1}"

MG=/tmp/mcpgate GM=/tmp/fakegmail AG=/tmp/gmail-agent
go build -o "$MG" ./cmd/mcpgate
go build -o "$GM" ./cmd/fakegmail
go build -o "$AG" ./cmd/gmail-agent

echo "model:    $MCPGATE_LLM_MODEL"
echo "endpoint: $MCPGATE_LLM_BASE"
echo
echo "======================================================================"
echo " 1) WITHOUT mcpgate — the model reads the poisoned invoice and obeys it"
echo "======================================================================"
"$AG" -- "$GM" 2>/dev/null

echo
echo "======================================================================"
echo " 2) THROUGH mcpgate — same model, same inbox (harm denied at the gate)"
echo "======================================================================"
"$AG" -- "$MG" \
  --read-tools list_messages,get_message \
  --action-tools send_message,delete_message \
  --redact off -- "$GM" 2>/dev/null
