# Claude session guidance — mcpgate

## What this is
A **transparent MCP proxy that gates an agent's tool use** — a firewall at the
model↔tools boundary. It wraps a real MCP server 1:1 (change the launch command),
pumps JSON-RPC through, and applies two controls. See [README.md](README.md).

## Settled stances (don't re-litigate — these came from a long design argument)
- **Tool boundary, not the prompt.** The dangerous injection is in what the
  agent autonomously reads mid-loop (email/web/doc = `tools/call` results), and
  the harm is the action after (`tools/call` requests). A prompt-intercepting
  proxy sits at neither end. This is NOT cyrano's reverse-proxy shape.
- **Gate is the boundary; filter is a layer.** The capability gate on
  `tools/call` requests fails **closed** — an action tool is denied unless
  granted. Redaction of tool results fails **open**. Lead on the gate.
- **GLiNER is for cooperative extraction, not injection detection.** Proven in
  the demo: GLiNER (`gliner_small`) returns zero spans for "prompt injection"
  labels even at threshold 0.2, but tags `attacker@evil.example` for "email
  address". So use it to extract exfil targets/PII from tool-call **arguments**
  (feeding the deterministic gate), NOT to "detect injections". An instruction
  isn't an entity.
- **No taint tracing through the model.** The proxy can't follow dataflow
  through the LLM (black box). Capability gating is enforced on the tool
  (decidable); cross-model taint is best-effort only.
- **Transparency is the hard part.** initialize/tools-list/notifications/ids
  pass through byte-faithfully; only a gated call or a redacted result deviates.
  Build/verify the invisible pump before adding hooks.

## Relationship to siblings
- `../cyrano` — clientless SSL VPN rewriter (reverse-proxy of web apps). Source
  of the HTTP/SSE proxy engineering, not the shape here.
- `../outis` — local PII tokenization for LLM chat (thin-client, human↔model).
  Its bidirectional-streaming redaction design informs the ingress filter.

## Test / run
```bash
go build ./... && go vet ./...
./demo/run.sh                                  # poisoned-email demo, builtin + GLiNER
sidecar/.venv/bin/python sidecar/redactor.py   # GLiNER filter on :8731 (optional)
```

## Status
Spike. Working: transparent stdio pump AND Streamable-HTTP reverse proxy (URL
swap, in-stream SSE redaction, `internal/proxy/http.go`), capability gate,
GLiNER filter, per-argument allowlists (`--arg-allow`, deny send to non-listed
recipients; `internal/extract`), a JSON config file (`--config`, flags override
it; `internal/config`), audit, a test suite that doubles as a spec
(`TestMoneyShot_...`, `TestHTTP_*`, `TestGate_ArgAllowlist`), and a demo agent
(`cmd/agent`) that follows an injected instruction live and hits the gate. Both transports run the
same `Hook`. Module path is `github.com/gazillion101/mcpgate` (personal nick,
NOT yovico — kept separate for now).
TODO: interactive approval path for `gated` tools, best-effort taint,
forward-MITM (fleet) proxy mode.
