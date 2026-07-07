#!/usr/bin/env bash
# Realistic demo: a "triage my inbox" agent against a Gmail-shaped MCP server
# whose inbox contains one prompt-injection email. Same agent, same inbox, run
# first without the gateway (the injection lands) and then through it (blocked).
set -euo pipefail
cd "$(dirname "$0")/.."

MG=/tmp/mcpgate GM=/tmp/fakegmail AG=/tmp/gmail-agent
go build -o "$MG" ./cmd/mcpgate
go build -o "$GM" ./cmd/fakegmail
go build -o "$AG" ./cmd/gmail-agent

echo "======================================================================"
echo " 1) WITHOUT mcpgate — agent talks straight to Gmail (the injection lands)"
echo "======================================================================"
"$AG" -- "$GM" 2>/dev/null

echo
echo "======================================================================"
echo " 2) THROUGH mcpgate — same agent, same inbox (harm blocked at the gate)"
echo "======================================================================"
"$AG" -- "$MG" \
  --read-tools list_messages,get_message \
  --action-tools send_message,delete_message \
  --redact off -- "$GM" 2>/dev/null
