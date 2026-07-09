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
- **A non-reasoning classifier detects injections; the reasoning is distilled
  out.** A guard LLM that READS untrusted content to judge it can be injected by
  that content. So the ingress filter is a distilled, non-injectable **ModernBERT
  classifier** (`../injection-detector`, HF `siberiancat/modernbert-prompt-injection`),
  called via the `/detect` sidecar. It's a FILTER — fails open — never the
  boundary. (GLiNER was tried first and dropped: it's an entity extractor and
  returns zero spans for "prompt injection" labels. Cooperative entity extraction
  still has a place — arg allowlists in `internal/extract` — just not injection
  detection. An instruction isn't an entity.)
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
./demo/run.sh                                  # poisoned-email demo, builtin + classifier
sidecar/.venv/bin/python sidecar/redactor.py   # ModernBERT detector on :8731 (--redact classifier)
```

## Status
Spike. Working: transparent stdio pump AND Streamable-HTTP reverse proxy (URL
swap, in-stream SSE redaction, `internal/proxy/http.go`), capability gate,
ModernBERT-classifier filter (`../injection-detector` via the `/detect` sidecar), per-argument allowlists (`--arg-allow`, deny send to non-listed
recipients; `internal/extract`), a JSON config file (`--config`, flags override
it; `internal/config`), audit — caught injections + denials flagged at WARN with
the payload span, optional `--audit-file` JSONL sink — a read-only localhost log
viewer (`mcpgate ui`, `internal/logview`), a token-gated localhost config editor
(`mcpgate config-ui`, `internal/configui` — Host allowlist vs rebinding, Origin
check vs CSRF, per-run token; refuses to bind off localhost), a test suite that doubles as a spec
(`TestMoneyShot_...`, `TestHTTP_*`, `TestGate_ArgAllowlist`), and a demo agent
(`cmd/agent`) that follows an injected instruction live and hits the gate, plus
a realistic Gmail-triage demo (`demo/gmail.sh`: `cmd/fakegmail` + `cmd/gmail-agent`
sharing `internal/mcpclient`) that shows the same agent breaching without the
gateway and safe through it — and `demo/gmail-llm.sh`, the same with a REAL model
(`internal/llm` speaks OpenAI Chat Completions → Ollama locally or LiteLLM for
Claude/DeepSeek/Gemini/OpenAI; verified live: qwen2.5-14b gets injected and the
gate blocks send/delete). Note: `fakegmail` list returns ids only (like real
Gmail) so the agent must open each message — that's how the poisoned body is read.
Both transports run the
same `Hook`. Module path is `github.com/gazillion101/mcpgate` (personal nick,
NOT yovico — kept separate for now).
TODO: interactive approval path for `gated` tools, best-effort taint,
forward-MITM (fleet) proxy mode.
