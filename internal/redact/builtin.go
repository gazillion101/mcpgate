package redact

import (
	"regexp"
	"unicode/utf8"
)

// Builtin is a tiny regex stub so the pipe is demoable without the model. It
// catches only the most obvious, low-effort injection phrasing — it is NOT the
// real detector. The Classifier (see classifier.go) replaces it: same Redactor
// interface, backed by a distilled ModernBERT detector with far better recall on
// paraphrased/novel injections. The builtin exists so the transport and
// result-rewriting are provable without the model.
type Builtin struct{ pats []*regexp.Regexp }

var builtinPatterns = []string{
	`(?i)ignore\s+(all\s+|any\s+)?(the\s+)?(previous|prior|above|earlier|preceding)\s+instructions?[^.!?\n]*[.!?]?`,
	`(?i)disregard\s+(all\s+|the\s+)?(previous|prior|above)[^.!?\n]*[.!?]?`,
	`(?i)you\s+are\s+now\s+[^.!?\n]*[.!?]?`,
	`(?i)(forward|send|exfiltrate|leak)\s+[^.!?\n]*\b(to\s+\S+@\S+|https?://\S+)[^.!?\n]*[.!?]?`,
}

func NewBuiltin() *Builtin {
	b := &Builtin{}
	for _, p := range builtinPatterns {
		b.pats = append(b.pats, regexp.MustCompile(p))
	}
	return b
}

func (b *Builtin) Name() string { return "builtin-stub" }

func (b *Builtin) Redact(text string) (string, []Span, error) {
	var spans []Span
	for _, re := range b.pats {
		for _, m := range re.FindAllStringIndex(text, -1) {
			spans = append(spans, Span{
				Start: utf8.RuneCountInString(text[:m[0]]),
				End:   utf8.RuneCountInString(text[:m[1]]),
				Label: "instruction-override",
				Score: 1.0,
			})
		}
	}
	if len(spans) == 0 {
		return text, nil, nil
	}
	return apply(text, spans), spans, nil
}
