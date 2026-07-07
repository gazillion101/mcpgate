package main

import "flag"

type flags struct {
	redact       string // builtin | gliner | off
	redactURL    string // gliner sidecar endpoint
	threshold    float64
	allowActions bool
	readTools    string // comma list classified as read (results filtered, calls allowed)
	actionTools  string // comma list classified as action (calls gated)

	httpListen string // if set, run as a Streamable-HTTP reverse proxy on this addr
	upstream   string // upstream MCP server URL (with --http-listen)
	argAllow   string // per-tool argument allowlists: "tool=glob,glob;tool2=glob"

	set *flag.FlagSet
}

func newFlags() *flags {
	f := &flags{set: flag.NewFlagSet("mcpgate", flag.ContinueOnError)}
	f.set.StringVar(&f.redact, "redact", "builtin", "ingress filter: builtin | gliner | off")
	f.set.StringVar(&f.redactURL, "redact-url", "http://127.0.0.1:8731/redact", "GLiNER sidecar URL")
	f.set.Float64Var(&f.threshold, "threshold", 0.5, "GLiNER score threshold")
	f.set.BoolVar(&f.allowActions, "allow-actions", false, "permit action tools without approval (demo/testing)")
	f.set.StringVar(&f.readTools, "read-tools", "", "comma-separated tools to classify as read")
	f.set.StringVar(&f.actionTools, "action-tools", "", "comma-separated tools to classify as action (gated)")
	f.set.StringVar(&f.httpListen, "http-listen", "", "run as a Streamable-HTTP proxy on this addr (e.g. 127.0.0.1:9000) instead of stdio")
	f.set.StringVar(&f.upstream, "upstream", "", "upstream MCP server URL (required with --http-listen)")
	f.set.StringVar(&f.argAllow, "arg-allow", "", `per-tool argument allowlist, e.g. "send_email=*@me.com,boss@x.com;post=https://hooks.acme.com/*"`)
	return f
}

func (f *flags) parse(args []string) error { return f.set.Parse(args) }
