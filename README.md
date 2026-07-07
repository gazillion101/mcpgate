# mcpgate

> **A firewall for AI agents that work on untrusted input.** It sits between an
> agent and its tools and redacts hidden instructions out of the content the
> agent reads — emails, web pages, tool results — before they reach the model,
> then blocks the risky tool calls those instructions would trigger.

_Open source (Apache-2.0) · Go, stdlib-only · stdio + Streamable HTTP · a working spike._

A **transparent MCP proxy that gates what an agent can do** — a firewall for the
agent's tool boundary, not a detector for its prompts.

You slip it into the pipe between an MCP client and a real MCP server. To the
client, nothing changed: it still sees the server's `initialize`, `tools/list`,
and notifications verbatim. But now every tool result is filtered on the way in,
and every action tool call is gated on the way out.

**Motivating example:** [protecting an OpenClaw personal agent](examples/openclaw.md)
— an unattended agent with broad access reads a booby-trapped email; mcpgate
keeps the hidden instruction from turning into arbitrary shell access.

## Why the tool boundary (and not the prompt)

The injection that matters in an agentic flow isn't in the user's prompt — it's
in what the agent **autonomously reads** mid-loop: an email body, a web page, a
retrieved document. The harm is the **action it takes after**: send, pay,
delete, exfiltrate. Both ends live at the agent's **tool boundary**, which in
MCP is exactly two message types:

| MCP message | direction | mcpgate control |
|-------------|-----------|-----------------|
| `tools/call` **result** | server → client | **filter** — redact injected spans before the model sees them |
| `tools/call` **request** | client → server | **gate** — deny action tools unless policy permits |

## Two controls, on purpose

- **Filter — fails open.** Redaction (GLiNER) is a detector; an injection
  crafted not to match its labels sails through. It thins the volume; it is not
  the boundary.
- **Gate — fails closed.** An action tool is denied unless it was affirmatively
  granted. Even a fully-poisoned model cannot reach a sink it never had. *This*
  is the boundary; the filter is the layer in front of it.

The design bet: you don't stop the injection, you make it **fire and reach
nothing**. Redaction catches the easy cases; the gate holds when it misses.

## What it deliberately does *not* claim

It does not trace taint **through the model**. The proxy sees the poisoned email
arrive and the `send_email` leave, but the dataflow between them runs through the
model — a black box it can't follow. So the capability gate is enforced on the
tool itself (decidable), and cross-model taint is best-effort (session/value
heuristics), never a guarantee. See `internal/policy` for the airtight half.

## Transparent by wrapping 1:1

Change the server's launch command in your MCP client config:

```jsonc
// before
"gmail": { "command": "npx", "args": ["@mcp/server-gmail"] }
// after — mcpgate spawns the real server and sits in its pipe
"gmail": { "command": "mcpgate",
           "args": ["--action-tools", "send_email,delete_email",
                    "--read-tools", "read_email,search",
                    "--redact", "gliner", "--",
                    "npx", "@mcp/server-gmail"] }
```

Or reverse-proxy a **remote (HTTPS) server** — same interceptor, second
transport — by swapping the URL the client points at:

```jsonc
// client points here instead of https://mcp.acme.com/mcp
"acme": { "url": "http://127.0.0.1:9000/mcp" }
```
```bash
mcpgate --http-listen 127.0.0.1:9000 --upstream https://mcp.acme.com/mcp \
        --action-tools send_email --read-tools read_email --redact gliner
```

mcpgate terminates the local hop and makes its own verified HTTPS connection
upstream — no MITM/CA needed. Streamed replies (SSE) are redacted event-by-event
as they flow; `Mcp-Session-Id` / `Authorization` pass through untouched.

## Configuration

Past a couple of servers, flags get unwieldy — put the policy in a JSON file and
pass `--config`. Any flag you also give on the command line **overrides** the
file (handy for one-off tweaks). See [`examples/config.example.json`](examples/config.example.json):

```json
{
  "redact": "gliner",
  "readTools": ["read_email", "search_inbox"],
  "actionTools": ["send_email", "delete_email"],
  "argAllow": { "send_email": ["*@yourcompany.com"] }
}
```

```jsonc
"gmail": { "command": "mcpgate",
           "args": ["--config", "/etc/mcpgate/gmail.json", "--", "npx", "@mcp/server-gmail"] }
```

**View the log.** With `auditFile` (or `--audit-file`) set, watch what your agent
did — and what got flagged — in a read-only localhost page:

```bash
mcpgate ui --audit-file ~/.local/share/mcpgate/audit.jsonl   # → http://127.0.0.1:8788
```

Caught injections and denials are highlighted, with the offending payload shown.
It only reads the file; keep it on localhost (the log holds attacker payloads).

**Edit the policy in a browser.** `mcpgate config-ui` serves a form to edit the
config file (tool classes, argument allowlists, redaction). It's a *write*
surface, so it's locked down: localhost-only, a per-run token gating every edit,
a Host allowlist (defeats DNS-rebinding), and a same-origin check (defeats CSRF):

```bash
mcpgate config-ui --config ~/.config/mcpgate/gmail.json
# → open http://127.0.0.1:8799/?token=<printed-token>
```

## Quickstart / demo

```bash
go build -o /tmp/mcpgate ./cmd/mcpgate
go build -o /tmp/fakemcp ./cmd/fakemcp
./demo/run.sh            # runs the poisoned-email demo, builtin + GLiNER

# GLiNER filter (optional, better recall than the built-in stub):
python3 -m venv sidecar/.venv && sidecar/.venv/bin/pip install -r sidecar/requirements.txt
sidecar/.venv/bin/python sidecar/redactor.py      # serves :8731
```

`fakemcp` exposes `read_email` (returns an email carrying a prompt injection)
and `send_email` (the sink). Through mcpgate you see the injection redacted out
of the read result, and the `send_email` the injection asked for denied at the
gate. `demo/run.sh` finishes by running `cmd/agent` — a real read→reason→act
loop — so you watch the agent act on the email's hidden instruction and the gate stop it.

## Tests

`go test ./...` — the suite doubles as an executable spec. Highlights:
`internal/proxy` proves byte-faithful passthrough and that a denied call never
reaches the server; `internal/policy` is the fail-closed gate table; and
`internal/hook` has `TestMoneyShot_InjectionFiresButReachesNothing` — the whole
thesis in one test.

## Layout

```
cmd/mcpgate    the proxy binary
cmd/fakemcp    a poisoned-email MCP server for the demo
cmd/agent      a tiny demo agent (credulous offline brain, or real Claude with ANTHROPIC_API_KEY)
internal/proxy transparent stdio pump (spawn child, two pumps, hook dispatch)
internal/jsonrpc  line-framed JSON-RPC, byte-faithful passthrough
internal/hook  the firewall: gate on tools/call request, redact on result
internal/policy the capability gate (fail-closed)
internal/extract email/URL extraction from tool args (for argument allowlists)
internal/redact the ingress filter: builtin stub + GLiNER sidecar client
internal/config JSON config loading; flags override the file
internal/audit  JSONL audit; caught injections + denials flagged at WARN with payload
internal/logview read-only localhost audit viewer (`mcpgate ui`)
internal/configui token-gated localhost config editor (`mcpgate config-ui`)
sidecar/       GLiNER redaction service (Python)
```

## Status

Spike. Working end-to-end: transparent stdio pump **and** Streamable-HTTP
reverse proxy (with in-stream SSE redaction), the capability gate with
per-argument allowlists (deny `send_email` to any address off the list), the
GLiNER filter, a JSON config file (`--config`; flags override it), an audit
trail that flags every caught injection and denial at WARN — with the payload —
and can persist to a file (`--audit-file`), a read-only localhost log viewer
(`mcpgate ui`), a token-gated localhost config editor (`mcpgate config-ui`), a
test suite that doubles as a spec, and a demo
agent that follows an injected instruction and hits the gate (`./demo/run.sh`,
`./demo/http.sh`). Not done: an interactive **approval** flow so `gated` tools
pause for a human instead of a hard deny, best-effort taint, and the
forward-MITM (fleet) proxy mode.
