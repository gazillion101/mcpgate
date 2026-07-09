// Package redact is the ingress filter: it screens tool results before they
// reach the model and quarantines injection content. The real backend is a
// distilled ModernBERT detector (see classifier.go); Builtin is a regex stub.
//
// It is a FILTER, not the boundary. It fails open: an injection crafted to not
// match the labels sails through. Pair it with the policy gate (which fails
// closed) — redaction thins the volume, the gate holds when redaction misses.
package redact

import (
	"encoding/json"
	"sort"
)

// Span is a half-open [Start,End) range of RUNE indices to strip.
type Span struct {
	Start int     `json:"start"`
	End   int     `json:"end"`
	Label string  `json:"label"`
	Score float64 `json:"score"`
}

// Redactor finds dangerous spans in a piece of untrusted text.
type Redactor interface {
	// Redact returns the cleaned text and the spans that were removed.
	Redact(text string) (string, []Span, error)
	// Name identifies the backend for audit/logging.
	Name() string
}

// apply splices [REDACTED] placeholders over the spans, using rune indices so
// multibyte content stays correct. Overlapping spans are merged.
func apply(text string, spans []Span) string {
	if len(spans) == 0 {
		return text
	}
	runes := []rune(text)
	n := len(runes)
	// Clamp and drop invalid spans.
	clean := spans[:0:0]
	for _, s := range spans {
		if s.Start < 0 {
			s.Start = 0
		}
		if s.End > n {
			s.End = n
		}
		if s.Start < s.End {
			clean = append(clean, s)
		}
	}
	sort.Slice(clean, func(i, j int) bool { return clean[i].Start < clean[j].Start })

	var out []rune
	cursor := 0
	for _, s := range clean {
		if s.Start < cursor { // overlap: skip the already-covered part
			if s.End <= cursor {
				continue
			}
			s.Start = cursor
		}
		out = append(out, runes[cursor:s.Start]...)
		out = append(out, []rune("⟦REDACTED:"+labelOr(s.Label, "injection")+"⟧")...)
		cursor = s.End
	}
	out = append(out, runes[cursor:]...)
	return string(out)
}

func labelOr(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

// Finding is one span that was stripped from a tool result. Text is the
// offending payload itself — safe and desirable to log, because it's the
// attacker's instruction, not the user's private data (unlike tool arguments).
type Finding struct {
	Label string  `json:"label"`
	Score float64 `json:"score"`
	Text  string  `json:"text"`
}

// RedactToolResult redacts the text content blocks of a `tools/call` result,
// preserving every other field. It returns the new result bytes and one Finding
// per stripped span, so each caught injection can be logged and flagged.
func RedactToolResult(result json.RawMessage, r Redactor) (json.RawMessage, []Finding, error) {
	var res map[string]json.RawMessage
	if err := json.Unmarshal(result, &res); err != nil {
		return result, nil, err // not a shape we redact; forward as-is
	}
	rawContent, ok := res["content"]
	if !ok {
		return result, nil, nil
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(rawContent, &blocks); err != nil {
		return result, nil, nil
	}

	var findings []Finding
	for _, b := range blocks {
		if string(b["type"]) != `"text"` {
			continue
		}
		var text string
		if err := json.Unmarshal(b["text"], &text); err != nil {
			continue
		}
		cleaned, spans, err := r.Redact(text)
		if err != nil || len(spans) == 0 {
			continue
		}
		for _, s := range spans {
			findings = append(findings, Finding{
				Label: labelOr(s.Label, "injection"),
				Score: s.Score,
				Text:  spanText(text, s),
			})
		}
		nb, _ := json.Marshal(cleaned)
		b["text"] = nb
	}
	if len(findings) == 0 {
		return result, nil, nil
	}

	newContent, err := json.Marshal(blocks)
	if err != nil {
		return result, nil, err
	}
	res["content"] = newContent
	newRes, err := json.Marshal(res)
	if err != nil {
		return result, nil, err
	}
	return newRes, findings, nil
}

// spanText returns the original substring a span covers, using rune indices
// (clamped), so the logged payload matches multibyte content correctly.
func spanText(text string, s Span) string {
	runes := []rune(text)
	a, b := s.Start, s.End
	if a < 0 {
		a = 0
	}
	if b > len(runes) {
		b = len(runes)
	}
	if a >= b {
		return ""
	}
	return string(runes[a:b])
}
