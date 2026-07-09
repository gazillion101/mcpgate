package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoad_DefaultsWhenNoPath(t *testing.T) {
	c, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if c.Redact != "builtin" || c.Threshold != 0.3 || c.AllowActions {
		t.Errorf("unexpected defaults: %+v", c)
	}
}

// A file sets some keys; the ones it omits keep their defaults.
func TestLoad_FileMergesOntoDefaults(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cfg.json")
	if err := os.WriteFile(path, []byte(`{
		"redact": "classifier",
		"actionTools": ["send_email"],
		"argAllow": {"send_email": ["*@me.com"]}
	}`), 0o644); err != nil {
		t.Fatal(err)
	}
	c, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Redact != "classifier" {
		t.Errorf("redact = %q, want classifier", c.Redact)
	}
	if c.Threshold != 0.3 || c.RedactURL == "" {
		t.Errorf("omitted keys lost their defaults: threshold=%v url=%q", c.Threshold, c.RedactURL)
	}
	if len(c.ActionTools) != 1 || c.ActionTools[0] != "send_email" {
		t.Errorf("actionTools = %v", c.ActionTools)
	}
	if g := c.ArgAllow["send_email"]; len(g) != 1 || g[0] != "*@me.com" {
		t.Errorf("argAllow = %v", c.ArgAllow)
	}
}

func TestLoad_BadJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	_ = os.WriteFile(path, []byte(`{ not json`), 0o644)
	if _, err := Load(path); err == nil {
		t.Error("expected an error on malformed JSON")
	}
}

func TestLoad_MissingFile(t *testing.T) {
	if _, err := Load("/no/such/mcpgate/config.json"); err == nil {
		t.Error("expected an error on a missing file")
	}
}

// Flags override the file; unrelated config values are left alone.
func TestApply_FlagsOverrideFile(t *testing.T) {
	c := Default()
	c.Redact = "classifier"
	off, allow := "off", true
	tools := []string{"a", "b"}

	c.Apply(Overrides{Redact: &off, AllowActions: &allow, ReadTools: &tools})

	if c.Redact != "off" {
		t.Errorf("override redact failed: %q", c.Redact)
	}
	if !c.AllowActions {
		t.Error("override allowActions failed")
	}
	if len(c.ReadTools) != 2 {
		t.Errorf("override readTools failed: %v", c.ReadTools)
	}
	if c.RedactURL != Default().RedactURL {
		t.Error("an untouched field was changed by Apply")
	}
}

func TestApply_NilOverridesChangeNothing(t *testing.T) {
	c := Default()
	c.Redact = "classifier"
	c.Apply(Overrides{}) // all nil
	if c.Redact != "classifier" {
		t.Errorf("empty Overrides changed config: %q", c.Redact)
	}
}
