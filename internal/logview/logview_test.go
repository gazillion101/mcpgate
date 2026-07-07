package logview

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func get(t *testing.T, s *Server, path string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
	return rec
}

// /events returns the valid JSONL lines as a JSON array, skipping junk.
func TestEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	_ = os.WriteFile(path, []byte(`{"level":"INFO","msg":"a"}
{"level":"WARN","msg":"injection_redacted","text":"ignore all previous"}
this-line-is-not-json
`), 0o644)
	s := &Server{AuditFile: path, MaxLines: 100}

	var events []map[string]any
	if err := json.Unmarshal(get(t, s, "/events").Body.Bytes(), &events); err != nil {
		t.Fatal(err)
	}
	if len(events) != 2 {
		t.Fatalf("want 2 valid events (junk skipped), got %d", len(events))
	}
	if events[1]["msg"] != "injection_redacted" || events[1]["text"] != "ignore all previous" {
		t.Errorf("payload not carried through: %v", events[1])
	}
}

func TestEvents_MissingFileIsEmptyArray(t *testing.T) {
	s := &Server{AuditFile: "/no/such/mcpgate/audit.jsonl"}
	if got := strings.TrimSpace(get(t, s, "/events").Body.String()); got != "[]" {
		t.Errorf("want [], got %q", got)
	}
}

func TestIndexServesHTML(t *testing.T) {
	rec := get(t, &Server{AuditFile: "x"}, "/")
	if ct := rec.Header().Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("content-type = %q", ct)
	}
	if !strings.Contains(rec.Body.String(), "mcpgate") {
		t.Error("index page missing")
	}
}

// It is read-only: writes are refused.
func TestReadOnly(t *testing.T) {
	rec := httptest.NewRecorder()
	(&Server{AuditFile: "x"}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/events", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST should be refused, got %d", rec.Code)
	}
}
