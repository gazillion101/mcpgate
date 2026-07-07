// Package redact is the ingress filter: it strips dangerous spans out of tool
// results before they reach the model. This is the GLiNER role — a
// description-conditioned span tagger over untrusted content.
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

// RedactToolResult redacts the text content blocks of a `tools/call` result,
// preserving every other field. Returns the new result bytes, the number of
// spans removed, and the distinct labels seen.
func RedactToolResult(result json.RawMessage, r Redactor) (json.RawMessage, int, []string, error) {
	var res map[string]json.RawMessage
	if err := json.Unmarshal(result, &res); err != nil {
		return result, 0, nil, err // not a shape we redact; forward as-is
	}
	rawContent, ok := res["content"]
	if !ok {
		return result, 0, nil, nil
	}
	var blocks []map[string]json.RawMessage
	if err := json.Unmarshal(rawContent, &blocks); err != nil {
		return result, 0, nil, nil
	}

	total := 0
	labelSet := map[string]struct{}{}
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
		nb, _ := json.Marshal(cleaned)
		b["text"] = nb
		total += len(spans)
		for _, s := range spans {
			labelSet[labelOr(s.Label, "injection")] = struct{}{}
		}
	}
	if total == 0 {
		return result, 0, nil, nil
	}

	newContent, err := json.Marshal(blocks)
	if err != nil {
		return result, 0, nil, err
	}
	res["content"] = newContent
	newRes, err := json.Marshal(res)
	if err != nil {
		return result, 0, nil, err
	}
	labels := make([]string, 0, len(labelSet))
	for l := range labelSet {
		labels = append(labels, l)
	}
	return newRes, total, labels, nil
}
