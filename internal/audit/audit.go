// Package audit writes one structured line per security-relevant event. It goes
// to stderr (or a file) — NEVER stdout, which carries the MCP protocol stream.
//
// The audit trail is a first-class output of the firewall, not a debug aid:
// every tool call, every gate decision, every redaction is recorded, so there
// is an independent record of what the agent tried to do — the "one plane
// across all the tools" that no individual MCP server provides.
package audit

import (
	"io"
	"log/slog"
	"os"
)

type Log struct{ l *slog.Logger }

// New writes JSON audit lines to w. If w is nil, stderr is used.
func New(w io.Writer) *Log {
	if w == nil {
		w = os.Stderr
	}
	return &Log{l: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))}
}

// ToolCall records a gate decision on an outbound tool call.
func (a *Log) ToolCall(tool, decision, reason string) {
	a.l.Info("tool_call", "tool", tool, "decision", decision, "reason", reason)
}

// Redaction records that a tool result had spans stripped before delivery.
func (a *Log) Redaction(tool string, count int, labels []string) {
	a.l.Info("redaction", "tool", tool, "spans", count, "labels", labels)
}

// Event records anything else worth a line.
func (a *Log) Event(msg string, kv ...any) { a.l.Info(msg, kv...) }
