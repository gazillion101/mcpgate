// Package extract pulls concrete identifiers (email addresses, URLs) out of a
// tool call's arguments, so the gate can allowlist them.
//
// This is the cooperative-extraction pattern: pull identifiers, feed a
// deterministic gate. For structured identifiers — emails, URLs — regex is
// actually MORE reliable than a model (no false negatives on well-formed
// values), so that's the core. A model-backed extractor can extend this to
// fuzzy entity types (person, org) the regex can't see; the gate logic is the
// same either way.
package extract

import (
	"encoding/json"
	"regexp"
)

// Target is one identifier found in a tool call's arguments.
type Target struct {
	Value string
	Type  string // "email" | "url"
}

var (
	emailRe = regexp.MustCompile(`[\w.+-]+@[\w-]+\.[\w.-]+`)
	urlRe   = regexp.MustCompile(`https?://[^\s"'<>)]+`)
)

// FromArgs walks every string value in the JSON arguments and returns the
// email/URL targets found, de-duplicated.
func FromArgs(args json.RawMessage) []Target {
	var out []Target
	seen := map[string]bool{}
	add := func(v, t string) {
		if k := t + "|" + v; !seen[k] {
			seen[k] = true
			out = append(out, Target{Value: v, Type: t})
		}
	}
	walkStrings(args, func(s string) {
		for _, m := range urlRe.FindAllString(s, -1) {
			add(m, "url")
		}
		for _, m := range emailRe.FindAllString(s, -1) {
			add(m, "email")
		}
	})
	return out
}

func walkStrings(raw json.RawMessage, fn func(string)) {
	if len(raw) == 0 {
		return
	}
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return
	}
	var rec func(any)
	rec = func(x any) {
		switch t := x.(type) {
		case string:
			fn(t)
		case []any:
			for _, e := range t {
				rec(e)
			}
		case map[string]any:
			for _, e := range t {
				rec(e)
			}
		}
	}
	rec(v)
}
