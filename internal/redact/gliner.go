package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// GLiNER calls the local GLiNER sidecar (see sidecar/redactor.py) to find spans
// that match natural-language labels describing injection content. The model
// runs out-of-process; the proxy stays a fast Go binary and just asks it
// "which spans of this tool result look like instructions to an agent?".
type GLiNER struct {
	url    string
	labels []string
	thresh float64
	client *http.Client
}

// DefaultLabels describe the adversarial target. Because injection tries NOT to
// match these, this is a fail-open filter — tune the labels, but never treat it
// as the boundary.
var DefaultLabels = []string{
	"instruction directed at an AI assistant",
	"command to ignore previous instructions",
	"prompt injection attempt",
	"request to exfiltrate or send data to an external address",
}

func NewGLiNER(url string, labels []string, threshold float64) *GLiNER {
	if len(labels) == 0 {
		labels = DefaultLabels
	}
	if threshold <= 0 {
		threshold = 0.5
	}
	return &GLiNER{
		url:    url,
		labels: labels,
		thresh: threshold,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (g *GLiNER) Name() string { return "gliner(" + g.url + ")" }

type glinerRequest struct {
	Text      string   `json:"text"`
	Labels    []string `json:"labels"`
	Threshold float64  `json:"threshold"`
}

type glinerResponse struct {
	Spans []Span `json:"spans"`
}

func (g *GLiNER) Redact(text string) (string, []Span, error) {
	body, _ := json.Marshal(glinerRequest{Text: text, Labels: g.labels, Threshold: g.thresh})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, g.url, bytes.NewReader(body))
	if err != nil {
		return text, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := g.client.Do(req)
	if err != nil {
		return text, nil, fmt.Errorf("gliner sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return text, nil, fmt.Errorf("gliner sidecar status %d", resp.StatusCode)
	}
	var out glinerResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return text, nil, err
	}
	if len(out.Spans) == 0 {
		return text, nil, nil
	}
	return apply(text, out.Spans), out.Spans, nil
}
