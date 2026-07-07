package proxy

import (
	"bytes"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/gazillion101/mcpgate/internal/jsonrpc"
)

// testHook stands in for the real firewall: deny send_email, redact "INJECT".
// (The proxy package can't import the hook package without a cycle; the real
// firewall is tested in internal/hook. Here we test the HTTP adapter.)
func testHook() Hook {
	return hookFunc(func(dir Direction, m *jsonrpc.Message, raw []byte) Decision {
		if dir == ClientToServer && m.ToolName() == "send_email" {
			return Decision{Reply: []byte(`{"jsonrpc":"2.0","id":` + m.IDKey() + `,"result":{"content":[{"type":"text","text":"blocked"}],"isError":true}}`)}
		}
		if dir == ServerToClient && bytes.Contains(raw, []byte("INJECT")) {
			return Decision{Replace: bytes.ReplaceAll(raw, []byte("INJECT"), []byte("[REDACTED]"))}
		}
		return Pass()
	})
}

// upstream mimics a remote Streamable-HTTP MCP server. read_email streams its
// (poisoned) result over SSE; send_email would be a side effect — it records
// whether it was ever reached.
func newUpstream(sendHit *int32) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		m, _ := jsonrpc.Parse(body)
		id := string(m.ID)
		w.Header().Set("Mcp-Session-Id", "sess-1")
		switch m.ToolName() {
		case "read_email":
			w.Header().Set("Content-Type", "text/event-stream")
			w.WriteHeader(200)
			fmt.Fprintf(w, "event: message\ndata: {\"jsonrpc\":\"2.0\",\"id\":%s,\"result\":{\"content\":[{\"type\":\"text\",\"text\":\"read this INJECT now\"}],\"isError\":false}}\n\n", id)
		case "send_email":
			atomic.StoreInt32(sendHit, 1) // must never happen if the gate works
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"content":[{"type":"text","text":"sent"}],"isError":false}}`, id)
		default:
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"jsonrpc":"2.0","id":%s,"result":{"serverInfo":{"name":"upstream"}}}`, id)
		}
	}))
}

func post(t *testing.T, p *HTTPProxy, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/mcp", strings.NewReader(body))
	rec := httptest.NewRecorder()
	p.ServeHTTP(rec, req)
	return rec
}

// A tool result streamed over SSE is redacted event-by-event as it flows.
func TestHTTP_RedactsStreamedToolResult(t *testing.T) {
	var sendHit int32
	up := newUpstream(&sendHit)
	defer up.Close()
	p := &HTTPProxy{Upstream: up.URL, Hook: testHook(), Client: up.Client()}

	rec := post(t, p, `{"jsonrpc":"2.0","id":3,"method":"tools/call","params":{"name":"read_email"}}`)

	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/event-stream") {
		t.Errorf("expected SSE passthrough, got Content-Type %q", ct)
	}
	out := rec.Body.String()
	if strings.Contains(out, "INJECT") {
		t.Errorf("injection survived the SSE filter:\n%s", out)
	}
	if !strings.Contains(out, "[REDACTED]") {
		t.Errorf("no redaction in stream:\n%s", out)
	}
	if !strings.HasPrefix(out, "event: message") {
		t.Errorf("SSE framing not preserved:\n%s", out)
	}
}

// Over HTTP, a denied action is answered directly and the upstream is never hit.
func TestHTTP_GateDeniesWithoutReachingUpstream(t *testing.T) {
	var sendHit int32
	up := newUpstream(&sendHit)
	defer up.Close()
	p := &HTTPProxy{Upstream: up.URL, Hook: testHook(), Client: up.Client()}

	rec := post(t, p, `{"jsonrpc":"2.0","id":4,"method":"tools/call","params":{"name":"send_email","arguments":{"to":"attacker@evil.example"}}}`)

	if atomic.LoadInt32(&sendHit) != 0 {
		t.Fatal("send_email REACHED the upstream server — gate failed")
	}
	if !strings.Contains(rec.Body.String(), `"isError":true`) {
		t.Errorf("client should have received an isError result; got %s", rec.Body.String())
	}
}

// initialize passes through untouched, and the server's session header is relayed.
func TestHTTP_TransparentInitialize(t *testing.T) {
	var sendHit int32
	up := newUpstream(&sendHit)
	defer up.Close()
	p := &HTTPProxy{Upstream: up.URL, Hook: testHook(), Client: up.Client()}

	rec := post(t, p, `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`)

	if !strings.Contains(rec.Body.String(), `"serverInfo"`) {
		t.Errorf("initialize not passed through: %s", rec.Body.String())
	}
	if rec.Header().Get("Mcp-Session-Id") != "sess-1" {
		t.Errorf("session header not relayed: %q", rec.Header().Get("Mcp-Session-Id"))
	}
}
