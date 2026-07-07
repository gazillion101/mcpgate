package policy

import (
	"encoding/json"
	"testing"
)

// The gate is the fail-closed wall: an action is denied unless policy
// affirmatively permits it, and an unrecognized tool is treated as an action
// (deny-by-default). This table IS the security contract.
func TestGate(t *testing.T) {
	classes := map[string]Class{"read_email": Read, "send_email": Action, "wire_money": Gated}
	cases := []struct {
		tool         string
		allowActions bool
		wantAllow    bool
	}{
		{"read_email", false, true},    // reads always flow (results get filtered)
		{"send_email", false, false},   // action, no grant → denied
		{"send_email", true, true},     // action, explicitly permitted → allowed
		{"wire_money", true, false},    // gated → denied even with allow-actions
		{"unknown_tool", false, false}, // unknown → deny-by-default
		{"unknown_tool", true, true},   // unknown falls to action; permitted → allowed
	}
	for _, c := range cases {
		g := New(classes, c.allowActions, nil)
		if got := g.Check(c.tool, nil); got.Allow != c.wantAllow {
			t.Errorf("Check(%q, allowActions=%v) = %v (%s), want allow=%v",
				c.tool, c.allowActions, got.Allow, got.Reason, c.wantAllow)
		}
	}
}

// An argument allowlist turns a blanket grant into a fine-grained one: the same
// tool is allowed to an approved recipient and denied to any other.
func TestGate_ArgAllowlist(t *testing.T) {
	g := New(
		map[string]Class{"send_email": Action},
		false, // NOT allow-actions: the allowlist is the only grant
		map[string][]string{"send_email": {"*@mycompany.com", "boss@partner.com"}},
	)
	args := func(to string) json.RawMessage {
		b, _ := json.Marshal(map[string]any{"to": to, "body": "hi"})
		return b
	}
	cases := []struct {
		to        string
		wantAllow bool
	}{
		{"colleague@mycompany.com", true},
		{"boss@partner.com", true},
		{"attacker@evil.example", false},
		{"", true}, // no recipient extracted → nothing to deny
	}
	for _, c := range cases {
		if got := g.Check("send_email", args(c.to)); got.Allow != c.wantAllow {
			t.Errorf("send_email to %q = %v (%s), want %v", c.to, got.Allow, got.Reason, c.wantAllow)
		}
	}
}
