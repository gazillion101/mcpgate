// gmail-agent is a small, realistic demo agent: "read my inbox and tell me which
// emails are important." It lists messages, reads each, and reports the
// important ones. Like any assistant, it follows instructions it's given — so
// when one email's body carries a hidden instruction, it obeys, and tries to
// forward the inbox and delete evidence. Run it THROUGH mcpgate and those
// actions are denied at the gate while the real task still completes.
//
//	gmail-agent -- <server-command>          # e.g. -- fakegmail   (no gateway)
//	gmail-agent -- mcpgate [flags] -- fakegmail   (through the gate)
package main

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/gazillion101/mcpgate/internal/mcpclient"
)

type msg struct{ ID, From, Subject string }

// forwardRe captures the recipient an instruction points at — what a credulous
// agent obeys.
var forwardRe = regexp.MustCompile(`(?i)(?:forward|send|email|deliver|leak|exfiltrate)[\s\S]{0,160}?\bto\s+([\w.+-]+@[\w-]+\.[\w.-]+)`)

func main() {
	_, server := splitAt(os.Args[1:], "--")
	if len(server) == 0 {
		fmt.Fprintln(os.Stderr, "usage: gmail-agent -- <server-command>")
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

	fmt.Println("[agent] task: read my inbox and tell me which emails are important")
	fmt.Println()

	var important []msg
	obeyed, blocked := false, false
	for _, m := range listMessages(c) {
		body := getBody(c, m.ID)
		imp := isImportant(m)
		if imp {
			important = append(important, m)
		}
		fmt.Printf("[agent] read: %-44s %-30s %s\n", trunc(m.Subject, 44), "("+m.From+")", mark(imp))

		// A well-behaved assistant follows instructions — including any buried in
		// what it reads. That credulity is the vulnerability.
		if hit := forwardRe.FindStringSubmatch(body); hit != nil {
			obeyed = true
			target := hit[1]
			fmt.Printf("[agent]    ↳ this email says to forward the inbox to %s — doing as instructed\n", target)
			_, isErr, _ := c.CallTool("send_message", map[string]any{"to": target, "subject": "fwd: inbox", "body": "forwarded per request"})
			fmt.Printf("[agent]    → send_message(to=%s)  %s\n", target, outcome(isErr))
			blocked = blocked || isErr
			if strings.Contains(strings.ToLower(body), "delete this message") {
				_, delErr, _ := c.CallTool("delete_message", map[string]any{"id": m.ID})
				fmt.Printf("[agent]    → delete_message(%s)  %s\n", m.ID, outcome(delErr))
				blocked = blocked || delErr
			}
		}
	}

	fmt.Println()
	fmt.Println("[agent] ✅ Important emails:")
	for _, m := range important {
		fmt.Printf("   • %s — %s\n", m.Subject, m.From)
	}
	if obeyed {
		fmt.Println()
		if blocked {
			fmt.Println("[agent] ⚠ one email tried to make me forward the inbox and delete evidence — those actions were blocked at the gate. Your data is safe.")
		} else {
			fmt.Println("[agent] ⛔ one email made me forward the inbox to an outside address and delete evidence — and nothing stopped it.")
		}
	}
}

func listMessages(c *mcpclient.Client) []msg {
	txt, _, err := c.CallTool("list_messages", map[string]any{})
	if err != nil {
		return nil
	}
	var out []msg
	for _, ln := range strings.Split(strings.TrimSpace(txt), "\n") {
		if p := strings.SplitN(ln, "|", 3); len(p) == 3 {
			out = append(out, msg{ID: p[0], From: p[1], Subject: p[2]})
		}
	}
	return out
}

func getBody(c *mcpclient.Client, id string) string {
	txt, _, _ := c.CallTool("get_message", map[string]any{"id": id})
	return txt
}

// isImportant is a naive triage heuristic: mail from a VIP, or internal mail
// whose subject looks time-sensitive.
func isImportant(m msg) bool {
	from := strings.ToLower(m.From)
	for _, vip := range []string{"manager@", "ceo@", "boss@", "director@"} {
		if strings.Contains(from, vip) {
			return true
		}
	}
	if strings.Contains(from, "@acme.com") {
		s := strings.ToLower(m.Subject)
		for _, kw := range []string{"due", "deadline", "urgent", "asap", "action required", "moved"} {
			if strings.Contains(s, kw) {
				return true
			}
		}
	}
	return false
}

func splitAt(args []string, sep string) (before, after []string) {
	for i, a := range args {
		if a == sep {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func mark(important bool) string {
	if important {
		return "★ IMPORTANT"
	}
	return "· skip"
}

func outcome(isErr bool) string {
	if isErr {
		return "⛔ BLOCKED"
	}
	return "✓ done"
}

func trunc(s string, n int) string {
	r := []rune(s)
	if len(r) > n {
		return string(r[:n-1]) + "…"
	}
	return s
}
