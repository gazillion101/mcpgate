// Package policy is the capability gate — the fail-closed wall.
//
// Redaction (the GLiNER filter) fails OPEN: if it misses an injected span, the
// poison reaches the model. This gate fails CLOSED: an action tool is denied
// unless policy affirmatively permits it, so even a fully-poisoned model cannot
// reach a sink it was never granted. That is the boundary; redaction is only
// the filter in front of it.
//
// A tool is read | action | gated. Action tools may additionally carry an
// argument allowlist: the call is permitted only if every identifier extracted
// from its arguments (recipient, URL) matches an allowed glob. That turns a
// blanket grant into "send_email, but only to *@mycompany.com" — cooperative
// extraction feeding a deterministic decision.
package policy

import (
	"encoding/json"
	"regexp"
	"strconv"
	"strings"

	"github.com/gazillion101/mcpgate/internal/extract"
)

type Class string

const (
	Read   Class = "read"   // source of untrusted content; always allowed, results get filtered
	Action Class = "action" // has side effects; allowed only if explicitly permitted
	Gated  Class = "gated"  // requires approval (out of band); denied in v1 headless mode
)

type Decision struct {
	Allow  bool
	Reason string
}

type Gate struct {
	classes      map[string]Class
	defaultClass Class
	allowActions bool
	argAllow     map[string][]*regexp.Regexp // tool -> allowed target globs
}

// New builds a gate. Unknown tools fall to Action (deny-by-default). argAllow
// maps a tool to a list of glob patterns; if present, that tool is permitted
// only when all extracted arguments match.
func New(classes map[string]Class, allowActions bool, argAllow map[string][]string) *Gate {
	if classes == nil {
		classes = map[string]Class{}
	}
	compiled := map[string][]*regexp.Regexp{}
	for tool, globs := range argAllow {
		for _, g := range globs {
			compiled[tool] = append(compiled[tool], globToRegexp(g))
		}
	}
	return &Gate{classes: classes, defaultClass: Action, allowActions: allowActions, argAllow: compiled}
}

func (g *Gate) ClassOf(tool string) Class {
	if c, ok := g.classes[tool]; ok {
		return c
	}
	return g.defaultClass
}

// Check decides whether a tools/call may proceed, inspecting its arguments when
// the tool has an allowlist.
func (g *Gate) Check(tool string, args json.RawMessage) Decision {
	switch g.ClassOf(tool) {
	case Read:
		return Decision{Allow: true, Reason: "read tool"}
	case Gated:
		return Decision{Allow: false, Reason: "requires approval (gated)"}
	case Action:
		if allow, ok := g.argAllow[tool]; ok {
			for _, t := range extract.FromArgs(args) {
				if !matchAny(allow, t.Value) {
					return Decision{Allow: false, Reason: t.Type + " " + strconv.Quote(t.Value) + " not in allowlist"}
				}
			}
			return Decision{Allow: true, Reason: "arguments within allowlist"}
		}
		if g.allowActions {
			return Decision{Allow: true, Reason: "action permitted by policy"}
		}
		return Decision{Allow: false, Reason: "action denied by default (no grant)"}
	default:
		return Decision{Allow: false, Reason: "unknown class, deny-by-default"}
	}
}

// globToRegexp turns a glob (only `*` is special) into an anchored,
// case-insensitive regexp. `*@acme.com` matches any address at that domain.
func globToRegexp(glob string) *regexp.Regexp {
	parts := strings.Split(glob, "*")
	for i := range parts {
		parts[i] = regexp.QuoteMeta(parts[i])
	}
	return regexp.MustCompile("(?i)^" + strings.Join(parts, ".*") + "$")
}

func matchAny(res []*regexp.Regexp, s string) bool {
	for _, re := range res {
		if re.MatchString(s) {
			return true
		}
	}
	return false
}
