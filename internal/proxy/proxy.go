// Package proxy is the transparent stdio pump. It spawns the real MCP server as
// a child, sits between the client (our stdin/stdout) and that child, and
// forwards every JSON-RPC line verbatim — except where a Hook chooses to
// rewrite a message (redact a tool result) or answer it directly (deny a tool
// call). The child's stderr is passed straight through so its logs still
// surface. Nothing but forwarded MCP messages is ever written to our stdout.
package proxy

import (
	"bufio"
	"context"
	"io"
	"os"
	"os/exec"
	"sync"

	"github.com/gazillion101/mcpgate/internal/jsonrpc"
)

// Direction of a message through the proxy.
type Direction int

const (
	// ClientToServer: a request or notification heading upstream.
	ClientToServer Direction = iota
	// ServerToClient: a response or notification heading downstream.
	ServerToClient
)

func (d Direction) String() string {
	if d == ClientToServer {
		return "client->server"
	}
	return "server->client"
}

// Decision is what a Hook wants done with a message.
//
// Exactly one outcome applies, checked in this order:
//   - Reply != nil  → send these bytes back to the ORIGINATING side; do not
//     forward (used to deny a tool call with a synthesized isError result).
//   - Drop          → forward nothing.
//   - Replace != nil→ forward these bytes instead of the original.
//   - otherwise     → forward the original bytes verbatim (transparent).
type Decision struct {
	Replace []byte
	Reply   []byte
	Drop    bool
}

// Pass is the transparent, do-nothing decision.
func Pass() Decision { return Decision{} }

// Hook inspects each message. It must be safe for concurrent use: the two pumps
// call it from separate goroutines.
type Hook interface {
	Inspect(dir Direction, msg *jsonrpc.Message, raw []byte) Decision
}

// Run wraps upstreamCmd, pumping JSON-RPC between clientIn/clientOut (our stdio)
// and the child. It returns when either side closes.
func Run(ctx context.Context, clientIn io.Reader, clientOut io.Writer, upstreamCmd *exec.Cmd, hook Hook) error {
	serverIn, err := upstreamCmd.StdinPipe()
	if err != nil {
		return err
	}
	serverOut, err := upstreamCmd.StdoutPipe()
	if err != nil {
		return err
	}
	upstreamCmd.Stderr = os.Stderr // pass the real server's logs straight through

	if err := upstreamCmd.Start(); err != nil {
		return err
	}

	// If the context is cancelled, tear the child down so the pumps unblock.
	go func() {
		<-ctx.Done()
		if upstreamCmd.Process != nil {
			_ = upstreamCmd.Process.Kill()
		}
	}()

	Bridge(clientIn, clientOut, serverIn, serverOut, hook)
	return upstreamCmd.Wait()
}

// Bridge runs the two transparent pumps between a client and an
// already-connected server over plain streams, returning once the client side
// closes and the server drains. Run wires the child process's pipes into it;
// tests wire in-memory pipes, so the proxy is exercised without a subprocess.
func Bridge(clientIn io.Reader, clientOut io.Writer, serverIn io.WriteCloser, serverOut io.Reader, hook Hook) {
	// clientOut is written by BOTH pumps (server responses, and deny-replies
	// from the client->server pump), so guard it.
	var outMu sync.Mutex
	writeClient := func(b []byte) error {
		outMu.Lock()
		defer outMu.Unlock()
		return writeLine(clientOut, b)
	}
	// serverIn is written only by the client->server pump: single writer.
	writeServer := func(b []byte) error { return writeLine(serverIn, b) }

	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		pump(clientIn, ClientToServer, hook, writeServer, writeClient)
		serverIn.Close() // EOF from client → tell the server we're done
	}()
	go func() {
		defer wg.Done()
		pump(serverOut, ServerToClient, hook, writeClient, writeServer)
	}()
	wg.Wait()
}

// pump reads newline-framed messages from r, runs the hook, and dispatches:
// forward onward, or reply back to the originating side.
func pump(r io.Reader, dir Direction, hook Hook, forward, reply func([]byte) error) {
	br := bufio.NewReaderSize(r, 1<<20)
	for {
		line, err := readLine(br)
		if len(line) > 0 {
			dispatch(line, dir, hook, forward, reply)
		}
		if err != nil {
			return // io.EOF or a read error ends this direction
		}
	}
}

func dispatch(line []byte, dir Direction, hook Hook, forward, reply func([]byte) error) {
	msg, perr := jsonrpc.Parse(line)
	if perr != nil {
		_ = forward(line) // not a JSON-RPC message we understand → verbatim
		return
	}
	switch d := hook.Inspect(dir, msg, line); {
	case d.Reply != nil:
		_ = reply(d.Reply)
	case d.Drop:
		// forward nothing
	case d.Replace != nil:
		_ = forward(d.Replace)
	default:
		_ = forward(line) // transparent passthrough of the original bytes
	}
}

// readLine returns one line without the trailing newline. On EOF it returns any
// trailing partial line alongside the error.
func readLine(br *bufio.Reader) ([]byte, error) {
	b, err := br.ReadBytes('\n')
	// Trim a single trailing \n (and \r if present).
	n := len(b)
	for n > 0 && (b[n-1] == '\n' || b[n-1] == '\r') {
		n--
	}
	return b[:n], err
}

func writeLine(w io.Writer, b []byte) error {
	buf := make([]byte, 0, len(b)+1)
	buf = append(buf, b...)
	buf = append(buf, '\n')
	_, err := w.Write(buf)
	return err
}
