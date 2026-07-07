// Streamable-HTTP adapter. Same Hook, new transport: instead of a spawned child
// over stdio, mcpgate is a local HTTP endpoint the client points at, and it
// reverse-proxies a remote MCP server over HTTPS. The interceptor is unchanged
// — gate on tools/call, redact on results — it just runs over HTTP framing and,
// for streamed replies, over Server-Sent Events.
//
// Point the client at this (URL swap) and set Upstream to the real server:
//
//	https://mcp.acme.com/mcp  ->  http://127.0.0.1:9000/mcp  (Upstream=https://mcp.acme.com/mcp)
//
// No MITM/CA is needed: mcpgate is a named endpoint the client dials and makes
// its own verified HTTPS connection upstream.
package proxy

import (
	"bufio"
	"bytes"
	"io"
	"net/http"
	"strings"

	"github.com/gazillion101/mcpgate/internal/jsonrpc"
)

type HTTPProxy struct {
	Upstream string       // real MCP server URL
	Hook     Hook         // the same interceptor as the stdio pump
	Client   *http.Client // for the upstream connection (verifies TLS)
}

// headers we carry through in each direction (transparency at the HTTP layer).
var (
	toUpstream   = []string{"Mcp-Session-Id", "MCP-Protocol-Version", "Authorization", "Last-Event-ID", "Accept", "Content-Type"}
	toClient     = []string{"Mcp-Session-Id", "MCP-Protocol-Version", "Content-Type"}
)

func (p *HTTPProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		p.handlePost(w, r)
	case http.MethodGet, http.MethodDelete:
		// GET = open the server->client SSE stream; DELETE = end session.
		p.forward(w, r, r.Method, nil)
	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (p *HTTPProxy) handlePost(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body", http.StatusBadRequest)
		return
	}
	if msg, perr := jsonrpc.Parse(body); perr == nil {
		switch d := p.Hook.Inspect(ClientToServer, msg, body); {
		case d.Reply != nil:
			// Gate deny: answer the client directly; upstream is never contacted.
			if sid := r.Header.Get("Mcp-Session-Id"); sid != "" {
				w.Header().Set("Mcp-Session-Id", sid)
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(d.Reply)
			return
		case d.Drop:
			w.WriteHeader(http.StatusAccepted)
			return
		case d.Replace != nil:
			body = d.Replace
		}
	}
	p.forward(w, r, http.MethodPost, body)
}

func (p *HTTPProxy) forward(w http.ResponseWriter, r *http.Request, method string, body []byte) {
	var rdr io.Reader
	if body != nil {
		rdr = bytes.NewReader(body)
	}
	up, err := http.NewRequestWithContext(r.Context(), method, p.Upstream, rdr)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	copyHeaders(up.Header, r.Header, toUpstream)
	if up.Header.Get("Accept") == "" {
		up.Header.Set("Accept", "application/json, text/event-stream")
	}

	resp, err := p.client().Do(up)
	if err != nil {
		http.Error(w, "upstream: "+err.Error(), http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	copyHeaders(w.Header(), resp.Header, toClient)

	if strings.HasPrefix(resp.Header.Get("Content-Type"), "text/event-stream") {
		w.WriteHeader(resp.StatusCode)
		p.streamSSE(w, resp.Body)
		return
	}

	// Single application/json message (or empty, e.g. 202 for a notification).
	rbody, _ := io.ReadAll(resp.Body)
	if len(rbody) > 0 {
		if m, err := jsonrpc.Parse(rbody); err == nil {
			if d := p.Hook.Inspect(ServerToClient, m, rbody); d.Replace != nil {
				rbody = d.Replace
			}
		}
	}
	w.WriteHeader(resp.StatusCode)
	_, _ = w.Write(rbody)
}

// streamSSE relays an SSE body, running the hook on each event's JSON-RPC
// message and flushing per event — no buffering, so streamed tool results are
// redacted as they flow.
func (p *HTTPProxy) streamSSE(w http.ResponseWriter, upstream io.Reader) {
	flusher, _ := w.(http.Flusher)
	br := bufio.NewReaderSize(upstream, 1<<20)
	var ev sseEvent
	emit := func() {
		if ev.empty() {
			return
		}
		if raw := ev.data(); raw != "" {
			out := []byte(raw)
			if m, err := jsonrpc.Parse(out); err == nil {
				if d := p.Hook.Inspect(ServerToClient, m, out); d.Replace != nil {
					out = d.Replace
				}
			}
			ev.setData(string(out))
		}
		io.WriteString(w, ev.encode())
		if flusher != nil {
			flusher.Flush()
		}
		ev = sseEvent{}
	}
	for {
		line, err := br.ReadString('\n')
		s := strings.TrimRight(line, "\r\n")
		switch {
		case s == "" && (len(line) > 0 || err == nil):
			emit() // blank line = event boundary
		case strings.HasPrefix(s, ":"):
			io.WriteString(w, s+"\n\n") // comment/keepalive, forwarded verbatim
			if flusher != nil {
				flusher.Flush()
			}
		case strings.HasPrefix(s, "data:"):
			ev.dataLines = append(ev.dataLines, strings.TrimPrefix(strings.TrimPrefix(s, "data:"), " "))
		case s != "":
			ev.fields = append(ev.fields, s) // event:, id:, retry:
		}
		if err != nil {
			emit()
			return
		}
	}
}

func (p *HTTPProxy) client() *http.Client {
	if p.Client != nil {
		return p.Client
	}
	return http.DefaultClient
}

func copyHeaders(dst, src http.Header, names []string) {
	for _, n := range names {
		if v := src.Get(n); v != "" {
			dst.Set(n, v)
		}
	}
}

// sseEvent accumulates one SSE event across lines.
type sseEvent struct {
	fields    []string // non-data lines: event:, id:, retry:
	dataLines []string
}

func (e sseEvent) empty() bool      { return len(e.fields) == 0 && len(e.dataLines) == 0 }
func (e sseEvent) data() string     { return strings.Join(e.dataLines, "\n") }
func (e *sseEvent) setData(s string) { e.dataLines = strings.Split(s, "\n") }
func (e sseEvent) encode() string {
	var b strings.Builder
	for _, f := range e.fields {
		b.WriteString(f)
		b.WriteByte('\n')
	}
	for _, d := range e.dataLines {
		b.WriteString("data: ")
		b.WriteString(d)
		b.WriteByte('\n')
	}
	b.WriteByte('\n')
	return b.String()
}
