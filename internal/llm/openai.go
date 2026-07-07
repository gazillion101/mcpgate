// Package llm is a minimal OpenAI-Chat-Completions tool-use loop. Because the
// OpenAI shape is the lingua franca, this one adapter drives them all: point
// BaseURL at Ollama (local), a LiteLLM proxy (which fans out to Anthropic /
// DeepSeek / Gemini / OpenAI), or any provider's OpenAI-compatible endpoint.
// Swapping providers is a base-url + model change, not code.
package llm

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Tool is an MCP tool exposed to the model as an OpenAI function.
type Tool struct {
	Name        string
	Description string
	Schema      json.RawMessage
}

// Event narrates the loop for display.
type Event struct {
	Kind    string // "tool_call" | "tool_result" | "final"
	Text    string
	Tool    string
	Args    map[string]any
	IsError bool
}

type Client struct {
	BaseURL  string // e.g. http://127.0.0.1:11434/v1
	Model    string
	Key      string // optional (Ollama needs none)
	HTTP     *http.Client
	MaxSteps int
}

func New(base, model, key string) *Client {
	return &Client{BaseURL: base, Model: model, Key: key, HTTP: &http.Client{Timeout: 180 * time.Second}, MaxSteps: 14}
}

type oaFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // a JSON string per the OpenAI spec
}
type oaToolCall struct {
	ID       string `json:"id"`
	Type     string `json:"type"`
	Function oaFunc `json:"function"`
}
type oaMessage struct {
	Role       string       `json:"role"`
	Content    string       `json:"content,omitempty"`
	ToolCalls  []oaToolCall `json:"tool_calls,omitempty"`
	ToolCallID string       `json:"tool_call_id,omitempty"`
}

// Run drives the tool-use loop: it asks the model, executes any tool calls via
// execute (which routes through mcpgate), feeds results back, and repeats until
// the model answers in plain text. onEvent narrates each step.
func (c *Client) Run(system, task string, tools []Tool,
	execute func(name string, args map[string]any) (string, bool),
	onEvent func(Event)) (string, error) {

	msgs := []oaMessage{{Role: "system", Content: system}, {Role: "user", Content: task}}
	oaTools := toOpenAITools(tools)

	steps := c.MaxSteps
	if steps <= 0 {
		steps = 14
	}
	for i := 0; i < steps; i++ {
		reply, err := c.complete(msgs, oaTools)
		if err != nil {
			return "", err
		}
		if len(reply.ToolCalls) == 0 {
			onEvent(Event{Kind: "final", Text: reply.Content})
			return reply.Content, nil
		}
		msgs = append(msgs, reply) // the assistant turn, with its tool calls
		for _, tc := range reply.ToolCalls {
			var args map[string]any
			_ = json.Unmarshal([]byte(tc.Function.Arguments), &args)
			onEvent(Event{Kind: "tool_call", Tool: tc.Function.Name, Args: args})
			result, isErr := execute(tc.Function.Name, args)
			onEvent(Event{Kind: "tool_result", Tool: tc.Function.Name, Text: result, IsError: isErr})
			msgs = append(msgs, oaMessage{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
	}
	return "", fmt.Errorf("reached step limit (%d)", steps)
}

func (c *Client) complete(msgs []oaMessage, tools []map[string]any) (oaMessage, error) {
	body, _ := json.Marshal(map[string]any{
		"model":       c.Model,
		"messages":    msgs,
		"tools":       tools,
		"tool_choice": "auto",
		"temperature": 0.2,
		"stream":      false,
	})
	req, err := http.NewRequest(http.MethodPost, c.BaseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return oaMessage{}, err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.Key != "" {
		req.Header.Set("Authorization", "Bearer "+c.Key)
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return oaMessage{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return oaMessage{}, fmt.Errorf("llm %d: %s", resp.StatusCode, b)
	}
	var out struct {
		Choices []struct {
			Message oaMessage `json:"message"`
		} `json:"choices"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return oaMessage{}, err
	}
	if len(out.Choices) == 0 {
		return oaMessage{}, fmt.Errorf("model returned no choices")
	}
	return out.Choices[0].Message, nil
}

func toOpenAITools(tools []Tool) []map[string]any {
	out := make([]map[string]any, 0, len(tools))
	for _, t := range tools {
		schema := t.Schema
		if len(schema) == 0 {
			schema = json.RawMessage(`{"type":"object","properties":{}}`)
		}
		out = append(out, map[string]any{
			"type": "function",
			"function": map[string]any{
				"name":        t.Name,
				"description": t.Description,
				"parameters":  schema,
			},
		})
	}
	return out
}
