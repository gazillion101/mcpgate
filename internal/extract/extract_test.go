package extract

import (
	"encoding/json"
	"testing"
)

func TestFromArgs(t *testing.T) {
	args := json.RawMessage(`{
		"to": "attacker@evil.example",
		"cc": ["ok@mycompany.com"],
		"body": "see https://evil.example/x and call me",
		"count": 5
	}`)
	got := FromArgs(args)

	want := map[string]string{
		"attacker@evil.example": "email",
		"ok@mycompany.com":      "email",
		"https://evil.example/x": "url",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d targets, want %d: %+v", len(got), len(want), got)
	}
	for _, tg := range got {
		if want[tg.Value] != tg.Type {
			t.Errorf("unexpected target %+v", tg)
		}
	}
}

func TestFromArgs_Empty(t *testing.T) {
	if got := FromArgs(nil); len(got) != 0 {
		t.Errorf("expected no targets from nil args, got %+v", got)
	}
}
