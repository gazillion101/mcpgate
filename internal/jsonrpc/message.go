// Package jsonrpc parses just enough of a JSON-RPC 2.0 message for mcpgate to
// route and inspect MCP traffic, while keeping opaque parts as RawMessage so
// anything we don't touch round-trips byte-faithfully.
//
// MCP's stdio transport frames each JSON-RPC message as one UTF-8 line with no
// embedded newlines, so the proxy works line-by-line: the ORIGINAL bytes are
// forwarded verbatim unless a hook explicitly rewrites the message. That is
// what makes the proxy transparent — the client sees the real server's
// `initialize`, `tools/list`, ids, and notifications unchanged.
package jsonrpc

import "encoding/json"

// Message is a parsed JSON-RPC 2.0 message (request, response, or notification).
type Message struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   json.RawMessage `json:"error,omitempty"`
}

// Parse decodes a single line into a Message. A parse error means "not a
// JSON-RPC message we understand" — the caller should forward the raw bytes.
func Parse(b []byte) (*Message, error) {
	var m Message
	if err := json.Unmarshal(b, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

func (m *Message) Marshal() ([]byte, error) { return json.Marshal(m) }

// IsRequest reports a request: has both a method and an id.
func (m *Message) IsRequest() bool { return m.Method != "" && len(m.ID) > 0 }

// IsNotification reports a notification: has a method but no id.
func (m *Message) IsNotification() bool { return m.Method != "" && len(m.ID) == 0 }

// IsResponse reports a response: has an id but no method.
func (m *Message) IsResponse() bool { return m.Method == "" && len(m.ID) > 0 }

// IDKey returns a stable string key for correlating a response to its request.
// The id may be a number or a string in JSON; the raw encoding is unique enough.
func (m *Message) IDKey() string { return string(m.ID) }

// ToolCallParams is the shape of `tools/call` request params.
type ToolCallParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments,omitempty"`
}

// ToolName extracts the tool name from a `tools/call` request, or "" if absent.
func (m *Message) ToolName() string {
	return m.toolCall().Name
}

// ToolArgs returns the raw arguments of a `tools/call` request, or nil.
func (m *Message) ToolArgs() json.RawMessage {
	return m.toolCall().Arguments
}

func (m *Message) toolCall() ToolCallParams {
	if m.Method != "tools/call" || len(m.Params) == 0 {
		return ToolCallParams{}
	}
	var p ToolCallParams
	_ = json.Unmarshal(m.Params, &p)
	return p
}
