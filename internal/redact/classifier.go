package redact

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// Classifier calls the local ModernBERT detector sidecar (see sidecar/redactor.py,
// POST /detect) — a distilled, non-injectable prompt-injection classifier. It
// returns one whole-message P(injection) rather than per-span tags; when that
// clears the threshold we treat the entire tool-result text as poisoned and
// quarantine it (a single span over the whole content).
//
// It is still a FILTER, not the boundary. It fails open — a novel attack it scores
// below threshold sails through. Pair it with the policy gate, which fails closed.
type Classifier struct {
	url    string
	thresh float64
	client *http.Client
}

func NewClassifier(url string, threshold float64) *Classifier {
	if threshold <= 0 {
		threshold = 0.3 // recall-favoring default; the filter is paired with the fail-closed gate
	}
	return &Classifier{
		url:    url,
		thresh: threshold,
		client: &http.Client{Timeout: 10 * time.Second},
	}
}

func (c *Classifier) Name() string { return "classifier(" + c.url + ")" }

type detectRequest struct {
	Text string `json:"text"`
}

type detectResponse struct {
	Score float64 `json:"score"`
}

func (c *Classifier) Redact(text string) (string, []Span, error) {
	if strings.TrimSpace(text) == "" {
		return text, nil, nil // nothing to score; avoid a degenerate whole-empty span
	}
	body, _ := json.Marshal(detectRequest{Text: text})
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url, bytes.NewReader(body))
	if err != nil {
		return text, nil, err
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.client.Do(req)
	if err != nil {
		return text, nil, fmt.Errorf("detector sidecar unreachable: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return text, nil, fmt.Errorf("detector sidecar status %d", resp.StatusCode)
	}
	var out detectResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return text, nil, err
	}
	if out.Score < c.thresh {
		return text, nil, nil
	}
	// Whole-message injection: quarantine the entire content block.
	span := Span{Start: 0, End: len([]rune(text)), Label: "injection", Score: out.Score}
	return apply(text, []Span{span}), []Span{span}, nil
}
