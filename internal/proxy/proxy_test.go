package proxy

import (
	"bufio"
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/gazillion101/mcpgate/internal/jsonrpc"
)

// recordingServer is an in-process stand-in for a real MCP server: it records
// every line it receives verbatim and replies to each request with a canned
// response, then closes its output when the client side drains.
type recordingServer struct {
	got      [][]byte
	response func(line []byte) []byte // return nil to send nothing (e.g. notifications)
}

func (s *recordingServer) serve(in io.Reader, out io.WriteCloser) {
	br := bufio.NewReaderSize(in, 1<<20)
	for {
		line, err := readLine(br)
		if len(line) > 0 {
			s.got = append(s.got, append([]byte(nil), line...))
			if s.response != nil {
				if resp := s.response(line); len(resp) > 0 {
					_ = writeLine(out, resp)
				}
			}
		}
		if err != nil {
			out.Close()
			return
		}
	}
}

type hookFunc func(Direction, *jsonrpc.Message, []byte) Decision

func (h hookFunc) Inspect(d Direction, m *jsonrpc.Message, raw []byte) Decision { return h(d, m, raw) }

func passHook() Hook {
	return hookFunc(func(Direction, *jsonrpc.Message, []byte) Decision { return Pass() })
}

// bridge wires an in-memory client and the given server through Bridge and
// returns what the client received.
func bridge(t *testing.T, clientLines []string, srv *recordingServer, hook Hook) []byte {
	t.Helper()
	serverInR, serverInW := io.Pipe()
	serverOutR, serverOutW := io.Pipe()
	go srv.serve(serverInR, serverOutW)

	var clientOut bytes.Buffer // writes are serialized by Bridge's outMu
	clientIn := strings.NewReader(strings.Join(clientLines, "\n") + "\n")
	Bridge(clientIn, &clientOut, serverInW, serverOutR, hook)
	return clientOut.Bytes()
}

func splitLines(b []byte) []string {
	var out []string
	for _, l := range strings.Split(strings.TrimRight(string(b), "\n"), "\n") {
		if l != "" {
			out = append(out, l)
		}
	}
	return out
}

// A no-op hook must forward every byte unchanged in both directions — the
// client sees the real server's messages exactly, which is what "transparent"
// means.
func TestBridge_TransparentPassthrough(t *testing.T) {
	client := []string{
		`{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"x":1}}`,
		`{"jsonrpc":"2.0","method":"notifications/initialized"}`,
		`{"jsonrpc":"2.0","id":2,"method":"tools/list"}`,
	}
	srv := &recordingServer{response: func(line []byte) []byte {
		m, _ := jsonrpc.Parse(line)
		if !m.IsRequest() {
			return nil // notifications get no reply
		}
		return []byte(`{"jsonrpc":"2.0","id":` + m.IDKey() + `,"result":{"ok":true}}`)
	}}

	got := bridge(t, client, srv, passHook())

	// client -> server: server saw exactly the client's lines, byte for byte.
	if len(srv.got) != len(client) {
		t.Fatalf("server got %d lines, want %d", len(srv.got), len(client))
	}
	for i := range client {
		if string(srv.got[i]) != client[i] {
			t.Errorf("line %d altered:\n got %s\nwant %s", i, srv.got[i], client[i])
		}
	}
	// server -> client: client saw exactly the two responses, byte for byte.
	want := []string{
		`{"jsonrpc":"2.0","id":1,"result":{"ok":true}}`,
		`{"jsonrpc":"2.0","id":2,"result":{"ok":true}}`,
	}
	if gotLines := splitLines(got); !equalLines(gotLines, want) {
		t.Errorf("client received:\n %v\nwant:\n %v", gotLines, want)
	}
}

// A hook that returns Reply answers the client directly; the message must NOT
// reach the server. This is the gate mechanism at the transport level.
func TestBridge_ReplyShortCircuitsTheServer(t *testing.T) {
	blocked := `{"jsonrpc":"2.0","id":7,"method":"tools/call","params":{"name":"send_email"}}`
	hook := hookFunc(func(d Direction, m *jsonrpc.Message, raw []byte) Decision {
		if d == ClientToServer && m.Method == "tools/call" {
			return Decision{Reply: []byte(`{"jsonrpc":"2.0","id":` + m.IDKey() + `,"result":{"blocked":true}}`)}
		}
		return Pass()
	})
	srv := &recordingServer{response: func([]byte) []byte { return nil }}

	got := bridge(t, []string{blocked}, srv, hook)

	if len(srv.got) != 0 {
		t.Fatalf("blocked call LEAKED to server: %s", srv.got)
	}
	if want := `{"jsonrpc":"2.0","id":7,"result":{"blocked":true}}`; !strings.Contains(string(got), want) {
		t.Errorf("client did not get the block reply; got %s", got)
	}
}

// A hook that returns Replace forwards rewritten bytes; only the targeted
// message changes.
func TestBridge_ReplaceRewritesForwardedBytes(t *testing.T) {
	line := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"x"}}`
	replaced := `{"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"REWRITTEN"}}`
	hook := hookFunc(func(d Direction, m *jsonrpc.Message, raw []byte) Decision {
		if d == ClientToServer {
			return Decision{Replace: []byte(replaced)}
		}
		return Pass()
	})
	srv := &recordingServer{response: func([]byte) []byte { return nil }}

	bridge(t, []string{line}, srv, hook)

	if len(srv.got) != 1 || string(srv.got[0]) != replaced {
		t.Errorf("server got %s, want %s", srv.got, replaced)
	}
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
