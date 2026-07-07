package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
)

// Client is a minimal MCP stdio client: it spawns the server command (which, in
// the demo, is `mcpgate -- <real server>`), so every call goes through the gate.
type Client struct {
	cmd *exec.Cmd
	in  io.WriteCloser
	out *bufio.Reader
	id  int
}

type rpcError struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// Tool is a tool as advertised by the server's tools/list.
type Tool struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	InputSchema json.RawMessage `json:"inputSchema"`
}

func Dial(command []string) (*Client, error) {
	cmd := exec.Command(command[0], command[1:]...)
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return nil, err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = os.Stderr // surface mcpgate's audit trail inline
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &Client{cmd: cmd, in: stdin, out: bufio.NewReaderSize(stdout, 1<<20)}, nil
}

func (c *Client) rpc(method string, params any) (json.RawMessage, *rpcError, error) {
	c.id++
	id := c.id
	req := map[string]any{"jsonrpc": "2.0", "id": id, "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	if _, err := c.in.Write(append(b, '\n')); err != nil {
		return nil, nil, err
	}
	for {
		line, err := c.out.ReadBytes('\n')
		if len(line) > 0 {
			var m struct {
				ID     json.RawMessage `json:"id"`
				Result json.RawMessage `json:"result"`
				Error  *rpcError       `json:"error"`
			}
			if json.Unmarshal(line, &m) == nil && string(m.ID) == strconv.Itoa(id) {
				return m.Result, m.Error, nil
			}
			// otherwise a notification or unrelated id — skip
		}
		if err != nil {
			return nil, nil, fmt.Errorf("no response to %s: %w", method, err)
		}
	}
}

func (c *Client) notify(method string, params any) error {
	req := map[string]any{"jsonrpc": "2.0", "method": method}
	if params != nil {
		req["params"] = params
	}
	b, _ := json.Marshal(req)
	_, err := c.in.Write(append(b, '\n'))
	return err
}

func (c *Client) Initialize() error {
	_, _, err := c.rpc("initialize", map[string]any{
		"protocolVersion": "2025-06-18",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "mcpgate-demo-agent", "version": "0.1.0"},
	})
	if err != nil {
		return err
	}
	return c.notify("notifications/initialized", nil)
}

func (c *Client) ListTools() ([]Tool, error) {
	res, _, err := c.rpc("tools/list", nil)
	if err != nil {
		return nil, err
	}
	var out struct {
		Tools []Tool `json:"tools"`
	}
	if err := json.Unmarshal(res, &out); err != nil {
		return nil, err
	}
	return out.Tools, nil
}

// CallTool invokes a tool and returns its text content plus whether it errored.
func (c *Client) CallTool(name string, args map[string]any) (string, bool, error) {
	res, rerr, err := c.rpc("tools/call", map[string]any{"name": name, "arguments": args})
	if err != nil {
		return "", true, err
	}
	if rerr != nil {
		return rerr.Message, true, nil
	}
	var r struct {
		Content []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"content"`
		IsError bool `json:"isError"`
	}
	if err := json.Unmarshal(res, &r); err != nil {
		return "", true, err
	}
	var text string
	for _, b := range r.Content {
		if b.Type == "text" {
			text += b.Text
		}
	}
	return text, r.IsError, nil
}

func (c *Client) Close() {
	c.in.Close()
	_ = c.cmd.Wait()
}
