// Package config loads mcpgate's policy from a JSON file, so the gate,
// allowlists, and redaction settings live in one editable place instead of a
// pile of flags. CLI flags remain as per-invocation overrides.
//
// This file is the source of truth a config UI would edit; the proxy only reads
// it. Absent keys keep their built-in defaults.
package config

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	Redact       string              `json:"redact,omitempty"`       // builtin | gliner | off
	RedactURL    string              `json:"redactUrl,omitempty"`    // gliner sidecar endpoint
	Threshold    float64             `json:"threshold,omitempty"`    // gliner score threshold
	AllowActions bool                `json:"allowActions,omitempty"` // permit action tools without a grant
	ReadTools    []string            `json:"readTools,omitempty"`    // classified read (results filtered, calls flow)
	ActionTools  []string            `json:"actionTools,omitempty"`  // classified action (calls gated)
	GatedTools   []string            `json:"gatedTools,omitempty"`   // classified gated (require approval; denied for now)
	ArgAllow     map[string][]string `json:"argAllow,omitempty"`     // per-tool argument allowlists (globs)
	HTTPListen   string              `json:"httpListen,omitempty"`   // Streamable-HTTP proxy listen addr
	Upstream     string              `json:"upstream,omitempty"`     // upstream MCP URL (with httpListen)
	AuditFile    string              `json:"auditFile,omitempty"`    // append JSONL audit here (in addition to stderr)
}

// Default returns the built-in defaults, used when no config file is given and
// as the base that a config file is merged onto.
func Default() *Config {
	return &Config{
		Redact:    "builtin",
		RedactURL: "http://127.0.0.1:8731/redact",
		Threshold: 0.5,
	}
}

// Load reads a JSON config, starting from Default() so keys absent from the file
// keep their defaults. An empty path returns the defaults.
func Load(path string) (*Config, error) {
	c := Default()
	if path == "" {
		return c, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	if err := json.Unmarshal(data, c); err != nil {
		return nil, fmt.Errorf("parse config %s: %w", path, err)
	}
	return c, nil
}

// Overrides carries CLI values; a non-nil field replaces the config value.
type Overrides struct {
	Redact       *string
	RedactURL    *string
	Threshold    *float64
	AllowActions *bool
	ReadTools    *[]string
	ActionTools  *[]string
	GatedTools   *[]string
	ArgAllow     *map[string][]string
	HTTPListen   *string
	Upstream     *string
	AuditFile    *string
}

// Apply overlays any set overrides onto the config (flags beat the file).
func (c *Config) Apply(o Overrides) {
	if o.Redact != nil {
		c.Redact = *o.Redact
	}
	if o.RedactURL != nil {
		c.RedactURL = *o.RedactURL
	}
	if o.Threshold != nil {
		c.Threshold = *o.Threshold
	}
	if o.AllowActions != nil {
		c.AllowActions = *o.AllowActions
	}
	if o.ReadTools != nil {
		c.ReadTools = *o.ReadTools
	}
	if o.ActionTools != nil {
		c.ActionTools = *o.ActionTools
	}
	if o.GatedTools != nil {
		c.GatedTools = *o.GatedTools
	}
	if o.ArgAllow != nil {
		c.ArgAllow = *o.ArgAllow
	}
	if o.HTTPListen != nil {
		c.HTTPListen = *o.HTTPListen
	}
	if o.Upstream != nil {
		c.Upstream = *o.Upstream
	}
	if o.AuditFile != nil {
		c.AuditFile = *o.AuditFile
	}
}
