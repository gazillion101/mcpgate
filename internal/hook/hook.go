// Package hook is "our thing": the firewall that hangs off the transparent
// pump. Two interception points on the same `tools/call` message:
//
//   - request  (client->server): the GATE. An action tool is denied unless
//     policy permits it — fail closed. A denied call never reaches the server;
//     the client gets a synthesized isError result instead.
//   - result   (server->client): the FILTER. Untrusted text in the tool result
//     is run through the redactor and dangerous spans are stripped before the
//     model sees them — fail open, thins the volume in front of the gate.
//
// Everything else passes through untouched, so the client still sees the real
// server's initialize / tools/list / notifications verbatim.
package hook

import (
	"encoding/json"
	"sync"

	"github.com/gazillion101/mcpgate/internal/audit"
	"github.com/gazillion101/mcpgate/internal/jsonrpc"
	"github.com/gazillion101/mcpgate/internal/policy"
	"github.com/gazillion101/mcpgate/internal/proxy"
	"github.com/gazillion101/mcpgate/internal/redact"
)

type Firewall struct {
	gate     *policy.Gate
	redactor redact.Redactor
	audit    *audit.Log

	mu      sync.Mutex
	pending map[string]pendingReq // request id -> what it was, to correlate responses
}

// pendingReq remembers an in-flight request so its response can be handled: the
// method (to know it's a tools/call) and the tool name (for the audit line).
type pendingReq struct {
	method string
	tool   string
}

func New(gate *policy.Gate, redactor redact.Redactor, a *audit.Log) *Firewall {
	return &Firewall{gate: gate, redactor: redactor, audit: a, pending: map[string]pendingReq{}}
}

func (f *Firewall) Inspect(dir proxy.Direction, msg *jsonrpc.Message, raw []byte) proxy.Decision {
	if dir == proxy.ClientToServer {
		return f.onClientToServer(msg)
	}
	return f.onServerToClient(msg)
}

func (f *Firewall) onClientToServer(msg *jsonrpc.Message) proxy.Decision {
	if msg.IsRequest() {
		f.mu.Lock()
		f.pending[msg.IDKey()] = pendingReq{method: msg.Method, tool: msg.ToolName()}
		f.mu.Unlock()
	}
	if msg.Method != "tools/call" {
		return proxy.Pass()
	}
	tool := msg.ToolName()
	dec := f.gate.Check(tool, msg.ToolArgs())
	if dec.Allow {
		f.audit.ToolCall(tool, "allow", dec.Reason)
		return proxy.Pass()
	}
	// Deny: answer the client directly, never forward to the server.
	f.audit.ToolCall(tool, "deny", dec.Reason)
	f.mu.Lock()
	delete(f.pending, msg.IDKey())
	f.mu.Unlock()
	return proxy.Decision{Reply: denyReply(msg.ID, tool, dec.Reason)}
}

func (f *Firewall) onServerToClient(msg *jsonrpc.Message) proxy.Decision {
	if !msg.IsResponse() {
		return proxy.Pass()
	}
	f.mu.Lock()
	pr := f.pending[msg.IDKey()]
	delete(f.pending, msg.IDKey())
	f.mu.Unlock()
	if pr.method != "tools/call" || len(msg.Result) == 0 {
		return proxy.Pass()
	}

	newResult, findings, err := redact.RedactToolResult(msg.Result, f.redactor)
	if err != nil {
		// Fail open on redactor error, but leave a record — a missed filter is
		// exactly what the gate exists to backstop.
		f.audit.Event("redact_error", "tool", pr.tool, "err", err.Error(), "backend", f.redactor.Name())
		return proxy.Pass()
	}
	if len(findings) == 0 {
		return proxy.Pass()
	}
	tool := pr.tool
	if tool == "" {
		tool = "tools/call"
	}
	// Every redaction is a caught injection attempt: log AND flag each one at
	// warn level, with the offending payload span, so it can drive an alert.
	for _, fd := range findings {
		f.audit.Flag("injection_redacted", "tool", tool, "label", fd.Label, "score", fd.Score, "text", fd.Text)
	}
	msg.Result = newResult
	out, err := msg.Marshal()
	if err != nil {
		return proxy.Pass()
	}
	return proxy.Decision{Replace: out}
}

// denyReply builds a JSON-RPC response carrying an MCP isError tool result, so
// the agent sees a clean "blocked" instead of a broken connection.
func denyReply(id json.RawMessage, tool, reason string) []byte {
	type textBlock struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	type toolResult struct {
		Content []textBlock `json:"content"`
		IsError bool        `json:"isError"`
	}
	type response struct {
		JSONRPC string          `json:"jsonrpc"`
		ID      json.RawMessage `json:"id"`
		Result  toolResult      `json:"result"`
	}
	r := response{
		JSONRPC: "2.0",
		ID:      id,
		Result: toolResult{
			Content: []textBlock{{Type: "text", Text: "⛔ mcpgate blocked tool '" + tool + "': " + reason}},
			IsError: true,
		},
	}
	b, _ := json.Marshal(r)
	return b
}
