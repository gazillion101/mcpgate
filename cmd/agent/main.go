// agent is a tiny demonstration agent. It speaks MCP as a client to a server
// launched THROUGH mcpgate, runs a read->reason->act loop, and shows an agent
// acting on a poisoned tool result — and the gate stopping the action.
//
//	agent [--task "..."] -- mcpgate [gate flags] -- <real server>
//
// With ANTHROPIC_API_KEY set it drives a real model; otherwise a credulous
// offline brain stands in for one that follows injected instructions.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/gazillion101/mcpgate/internal/mcpclient"
)

// Tool aliases the shared client's Tool so brain.go's signatures stay unchanged.
type Tool = mcpclient.Tool

func main() {
	flagArgs, server := splitAt(os.Args[1:], "--")
	fs := flag.NewFlagSet("agent", flag.ExitOnError)
	task := fs.String("task", "Read my latest email and summarize it for me.", "the agent's task")
	steps := fs.Int("steps", 6, "max agent steps")
	_ = fs.Parse(flagArgs)

	if len(server) == 0 {
		fmt.Fprintln(os.Stderr, "usage: agent [--task ...] -- <server-command>  (e.g. -- mcpgate ... -- fakemcp)")
		os.Exit(2)
	}

	c, err := mcpclient.Dial(server)
	if err != nil {
		fmt.Fprintln(os.Stderr, "dial:", err)
		os.Exit(1)
	}
	defer c.Close()
	if err := c.Initialize(); err != nil {
		fmt.Fprintln(os.Stderr, "initialize:", err)
		os.Exit(1)
	}
	tools, err := c.ListTools()
	if err != nil {
		fmt.Fprintln(os.Stderr, "tools/list:", err)
		os.Exit(1)
	}

	brain := chooseBrain()
	fmt.Printf("agent brain : %s\n", brain.Name())
	fmt.Printf("tools seen  : %s\n", toolNames(tools))
	fmt.Printf("task        : %s\n\n", *task)

	var tr []Turn
	for i := 0; i < *steps; i++ {
		act, err := brain.Decide(*task, tools, tr)
		if err != nil {
			fmt.Fprintln(os.Stderr, "brain:", err)
			os.Exit(1)
		}
		if act.IsFinal {
			fmt.Printf("[agent] ✅ %s\n", act.Final)
			return
		}
		if act.Why != "" {
			fmt.Printf("[agent] %s\n", act.Why)
		}
		fmt.Printf("[agent] → %s(%s)\n", act.Tool, jsonArgs(act.Args))
		result, isErr, err := c.CallTool(act.Tool, act.Args)
		if err != nil {
			fmt.Fprintln(os.Stderr, "call:", err)
			os.Exit(1)
		}
		tag := "result"
		if isErr {
			tag = "BLOCKED"
		}
		fmt.Printf("[server] %s: %s\n\n", tag, oneLine(result, 300))
		tr = append(tr, Turn{Tool: act.Tool, Args: act.Args, Result: result, IsError: isErr})
	}
	fmt.Println("[agent] (step limit reached)")
}

func chooseBrain() Brain {
	if key := os.Getenv("ANTHROPIC_API_KEY"); key != "" {
		return NewAnthropicBrain(key)
	}
	return CredulousBrain{}
}

// splitAt divides args at the first sep.
func splitAt(args []string, sep string) (before, after []string) {
	for i, a := range args {
		if a == sep {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func toolNames(tools []Tool) string {
	var n []string
	for _, t := range tools {
		n = append(n, t.Name)
	}
	b, _ := json.Marshal(n)
	return string(b)
}

func jsonArgs(a map[string]any) string {
	if len(a) == 0 {
		return ""
	}
	b, _ := json.Marshal(a)
	return string(b)
}

func oneLine(s string, max int) string {
	s = replaceNewlines(s)
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}

func replaceNewlines(s string) string {
	out := make([]rune, 0, len(s))
	for _, r := range s {
		if r == '\n' || r == '\r' {
			out = append(out, ' ')
			continue
		}
		out = append(out, r)
	}
	return string(out)
}
