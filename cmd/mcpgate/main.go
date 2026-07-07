// mcpgate is a transparent MCP proxy. It wraps a real MCP server 1:1 —
//
//	mcpgate [flags] -- <server-command> [server-args...]
//
// — spawning it as a child and pumping JSON-RPC between the client and the
// server, redacting untrusted tool-result content (the fail-open filter) and
// gating action tool calls (the fail-closed wall) as they pass.
package main

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"strings"
	"syscall"

	"github.com/gazillion101/mcpgate/internal/audit"
	"github.com/gazillion101/mcpgate/internal/config"
	"github.com/gazillion101/mcpgate/internal/hook"
	"github.com/gazillion101/mcpgate/internal/policy"
	"github.com/gazillion101/mcpgate/internal/proxy"
	"github.com/gazillion101/mcpgate/internal/redact"
)

func main() {
	flagArgs, serverCmd := splitArgs(os.Args[1:])

	fs := newFlags()
	if err := fs.parse(flagArgs); err != nil {
		fatal(err.Error())
	}

	cfg, err := config.Load(fs.configPath)
	if err != nil {
		fatal(err.Error())
	}
	cfg.Apply(fs.overrides()) // explicitly-set flags beat the file

	a := audit.New(os.Stderr)
	gate := policy.New(classesFrom(cfg.ReadTools, cfg.ActionTools), cfg.AllowActions, cfg.ArgAllow)
	redactor := buildRedactor(cfg)
	fw := hook.New(gate, redactor, a)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// HTTP mode: reverse-proxy a remote Streamable-HTTP MCP server.
	if cfg.HTTPListen != "" {
		if cfg.Upstream == "" {
			fatal("upstream is required with http-listen (set it in the config or with --upstream)")
		}
		hp := &proxy.HTTPProxy{Upstream: cfg.Upstream, Hook: fw}
		a.Event("mcpgate_http_start", "listen", cfg.HTTPListen, "upstream", cfg.Upstream,
			"redactor", redactor.Name(), "allow_actions", cfg.AllowActions)
		srv := &http.Server{Addr: cfg.HTTPListen, Handler: http.HandlerFunc(hp.ServeHTTP)}
		go func() { <-ctx.Done(); _ = srv.Close() }()
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fatal(err.Error())
		}
		return
	}

	// stdio mode: wrap a locally-spawned MCP server.
	if len(serverCmd) == 0 {
		fatal("usage: mcpgate [flags] -- <server-command> [args...]   (or --http-listen ADDR --upstream URL)")
	}
	a.Event("mcpgate_start",
		"upstream", strings.Join(serverCmd, " "),
		"redactor", redactor.Name(),
		"allow_actions", cfg.AllowActions)
	cmd := exec.CommandContext(ctx, serverCmd[0], serverCmd[1:]...)
	if err := proxy.Run(ctx, os.Stdin, os.Stdout, cmd, fw); err != nil {
		a.Event("mcpgate_exit", "err", err.Error())
	}
}

// buildRedactor selects the ingress filter backend.
func buildRedactor(cfg *config.Config) redact.Redactor {
	switch cfg.Redact {
	case "off":
		return noopRedactor{}
	case "gliner":
		return redact.NewGLiNER(cfg.RedactURL, nil, cfg.Threshold)
	default: // "builtin"
		return redact.NewBuiltin()
	}
}

type noopRedactor struct{}

func (noopRedactor) Redact(t string) (string, []redact.Span, error) { return t, nil, nil }
func (noopRedactor) Name() string                                   { return "off" }

func classesFrom(read, action []string) map[string]policy.Class {
	classes := map[string]policy.Class{}
	for _, t := range read {
		classes[t] = policy.Read
	}
	for _, t := range action {
		classes[t] = policy.Action
	}
	return classes
}

// parseArgAllow parses "tool=glob,glob;tool2=glob" into a per-tool glob list.
func parseArgAllow(s string) map[string][]string {
	out := map[string][]string{}
	for _, entry := range strings.Split(s, ";") {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		tool, globs, ok := strings.Cut(entry, "=")
		if !ok {
			continue
		}
		out[strings.TrimSpace(tool)] = splitList(globs)
	}
	return out
}

func splitList(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// splitArgs divides argv at the first "--": before it are mcpgate flags, after
// it is the upstream server command.
func splitArgs(args []string) (flagArgs, upstream []string) {
	for i, a := range args {
		if a == "--" {
			return args[:i], args[i+1:]
		}
	}
	return args, nil
}

func fatal(msg string) {
	fmt.Fprintln(os.Stderr, "mcpgate: "+msg)
	os.Exit(2)
}
