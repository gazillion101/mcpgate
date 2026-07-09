package configui

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gazillion101/mcpgate/internal/config"
)

const tok = "secret-token"

func newServer(t *testing.T) (*Server, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "config.json")
	return &Server{ConfigPath: path, Token: tok}, path
}

func local(method, path, body string) *http.Request {
	r := httptest.NewRequest(method, "http://127.0.0.1:8799"+path, strings.NewReader(body))
	r.Host = "127.0.0.1:8799"
	return r
}

// Reading the config requires the token.
func TestGetConfig_RequiresToken(t *testing.T) {
	s, _ := newServer(t)
	for _, tc := range []struct{ name, token string }{{"none", ""}, {"wrong", "nope"}} {
		rec := httptest.NewRecorder()
		r := local(http.MethodGet, "/config", "")
		if tc.token != "" {
			r.Header.Set("X-MCPGate-Token", tc.token)
		}
		s.ServeHTTP(rec, r)
		if rec.Code != http.StatusUnauthorized {
			t.Errorf("%s token: got %d, want 401", tc.name, rec.Code)
		}
	}
}

func TestGetConfig_WithToken(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	r := local(http.MethodGet, "/config", "")
	r.Header.Set("X-MCPGate-Token", tok)
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusOK {
		t.Fatalf("got %d", rec.Code)
	}
	var c config.Config
	if err := json.Unmarshal(rec.Body.Bytes(), &c); err != nil {
		t.Fatal(err)
	}
	if c.Redact != "builtin" {
		t.Errorf("defaults not returned: %+v", c)
	}
}

// A valid, same-origin, authenticated POST writes the file.
func TestPostConfig_WritesFile(t *testing.T) {
	s, path := newServer(t)
	rec := httptest.NewRecorder()
	r := local(http.MethodPost, "/config", `{"redact":"classifier","actionTools":["send_email"],"argAllow":{"send_email":["*@me.com"]}}`)
	r.Header.Set("X-MCPGate-Token", tok)
	r.Header.Set("Origin", "http://127.0.0.1:8799")
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("got %d: %s", rec.Code, rec.Body)
	}
	c, err := config.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if c.Redact != "classifier" || len(c.ActionTools) != 1 {
		t.Errorf("config not persisted: %+v", c)
	}
}

// CSRF defense: a write carrying a foreign Origin is refused even with a token.
func TestPostConfig_CrossOriginRefused(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	r := local(http.MethodPost, "/config", "{}")
	r.Header.Set("X-MCPGate-Token", tok)
	r.Header.Set("Origin", "https://evil.example")
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("cross-origin write: got %d, want 403", rec.Code)
	}
}

// DNS-rebinding defense: a request with a foreign Host is refused up front.
func TestForbiddenHost(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	r := local(http.MethodGet, "/config", "")
	r.Host = "evil.example" // what a rebinding attack presents
	r.Header.Set("X-MCPGate-Token", tok)
	s.ServeHTTP(rec, r)
	if rec.Code != http.StatusForbidden {
		t.Errorf("rebinding host: got %d, want 403", rec.Code)
	}
}

func TestIndexServesHTML(t *testing.T) {
	s, _ := newServer(t)
	rec := httptest.NewRecorder()
	s.ServeHTTP(rec, local(http.MethodGet, "/", ""))
	if !strings.Contains(rec.Body.String(), "mcpgate") {
		t.Error("index page missing")
	}
}
