package main

import (
	"flag"

	"github.com/gazillion101/mcpgate/internal/config"
)

type flags struct {
	configPath string // JSON config file; flags below override it
	redact       string // builtin | classifier | off
	redactURL    string // detector sidecar endpoint
	threshold    float64
	allowActions bool
	readTools    string // comma list classified as read (results filtered, calls allowed)
	actionTools  string // comma list classified as action (calls gated)

	httpListen string // if set, run as a Streamable-HTTP reverse proxy on this addr
	upstream   string // upstream MCP server URL (with --http-listen)
	argAllow   string // per-tool argument allowlists: "tool=glob,glob;tool2=glob"
	auditFile  string // append JSONL audit here (in addition to stderr)

	set *flag.FlagSet
}

func newFlags() *flags {
	f := &flags{set: flag.NewFlagSet("mcpgate", flag.ContinueOnError)}
	f.set.StringVar(&f.configPath, "config", "", "path to a JSON config file (flags below override it)")
	f.set.StringVar(&f.redact, "redact", "builtin", "ingress filter: builtin | classifier | off")
	f.set.StringVar(&f.redactURL, "redact-url", "http://127.0.0.1:8731/detect", "detector sidecar URL")
	f.set.Float64Var(&f.threshold, "threshold", 0.1, "detector injection-probability threshold (0-1; lower = more sensitive)")
	f.set.BoolVar(&f.allowActions, "allow-actions", false, "permit action tools without approval (demo/testing)")
	f.set.StringVar(&f.readTools, "read-tools", "", "comma-separated tools to classify as read")
	f.set.StringVar(&f.actionTools, "action-tools", "", "comma-separated tools to classify as action (gated)")
	f.set.StringVar(&f.httpListen, "http-listen", "", "run as a Streamable-HTTP proxy on this addr (e.g. 127.0.0.1:9000) instead of stdio")
	f.set.StringVar(&f.upstream, "upstream", "", "upstream MCP server URL (required with --http-listen)")
	f.set.StringVar(&f.argAllow, "arg-allow", "", `per-tool argument allowlist, e.g. "send_email=*@me.com,boss@x.com;post=https://hooks.acme.com/*"`)
	f.set.StringVar(&f.auditFile, "audit-file", "", "append JSONL audit to this file (in addition to stderr)")
	return f
}

func (f *flags) parse(args []string) error { return f.set.Parse(args) }

// overrides returns only the flags the user explicitly set, so they take
// precedence over the config file (and unset flags leave the file's values).
func (f *flags) overrides() config.Overrides {
	set := map[string]bool{}
	f.set.Visit(func(fl *flag.Flag) { set[fl.Name] = true })

	var o config.Overrides
	if set["redact"] {
		o.Redact = &f.redact
	}
	if set["redact-url"] {
		o.RedactURL = &f.redactURL
	}
	if set["threshold"] {
		o.Threshold = &f.threshold
	}
	if set["allow-actions"] {
		o.AllowActions = &f.allowActions
	}
	if set["read-tools"] {
		v := splitList(f.readTools)
		o.ReadTools = &v
	}
	if set["action-tools"] {
		v := splitList(f.actionTools)
		o.ActionTools = &v
	}
	if set["arg-allow"] {
		v := parseArgAllow(f.argAllow)
		o.ArgAllow = &v
	}
	if set["http-listen"] {
		o.HTTPListen = &f.httpListen
	}
	if set["upstream"] {
		o.Upstream = &f.upstream
	}
	if set["audit-file"] {
		o.AuditFile = &f.auditFile
	}
	return o
}
