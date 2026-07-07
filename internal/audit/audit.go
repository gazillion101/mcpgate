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

// New writes JSON audit lines to w. If w is nil, stderr is used. Callers that
// want a persistent record pass an io.MultiWriter(stderr, file).
func New(w io.Writer) *Log {
	if w == nil {
		w = os.Stderr
	}
	return &Log{l: slog.New(slog.NewJSONHandler(w, &slog.HandlerOptions{Level: slog.LevelInfo}))}
}

// Event records a routine line at info level (startup, non-security events).
func (a *Log) Event(msg string, kv ...any) { a.l.Info(msg, kv...) }

// Flag records a security-relevant event at WARN level, so it stands out from
// routine info lines and can drive an alert: `jq 'select(.level=="WARN")'`.
// Redactions (caught injections) and denials go through here.
func (a *Log) Flag(msg string, kv ...any) { a.l.Warn(msg, kv...) }

// ToolCall records a gate decision. A denial is a security event → flagged at
// WARN; an allow is routine → info.
func (a *Log) ToolCall(tool, decision, reason string) {
	if decision == "deny" {
		a.Flag("tool_call", "tool", tool, "decision", decision, "reason", reason)
		return
	}
	a.Event("tool_call", "tool", tool, "decision", decision, "reason", reason)
}
