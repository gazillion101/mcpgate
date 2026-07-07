// Package configui is a localhost editor for the JSON config file. Unlike the
// read-only log viewer, this is a WRITE surface — it can change the firewall's
// policy — so it is a high-value target for two attackers that can reach
// 127.0.0.1: a malicious web page in your browser (DNS-rebinding / CSRF) and the
// very agent being contained. It is locked down accordingly:
//
//   - a per-run auth TOKEN required on every /config request (constant-time);
//   - a Host allowlist on every request (defeats DNS-rebinding);
//   - a same-origin check on writes (defeats CSRF);
//   - localhost bind (enforced by the caller).
//
// The editor edits a file; mcpgate reads that file at launch. Changes apply when
// the client next spawns the wrapped server.
package configui

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/gazillion101/mcpgate/internal/config"
)

type Server struct {
	ConfigPath string
	Token      string
}

// NewToken returns a fresh 128-bit hex token for a run of the editor.
func NewToken() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	// Host allowlist on EVERY request — a DNS-rebinding attack arrives with the
	// attacker's hostname in Host, not 127.0.0.1.
	if !localHost(r.Host) {
		http.Error(w, "forbidden host", http.StatusForbidden)
		return
	}
	switch {
	case r.Method == http.MethodGet && r.URL.Path == "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	case r.URL.Path == "/config" && r.Method == http.MethodGet:
		if !s.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		s.handleGet(w)
	case r.URL.Path == "/config" && r.Method == http.MethodPost:
		if !s.authed(r) {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !sameOrigin(r) { // CSRF defense: a cross-site POST carries a foreign Origin
			http.Error(w, "cross-origin write refused", http.StatusForbidden)
			return
		}
		s.handlePost(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (s *Server) authed(r *http.Request) bool {
	tok := r.Header.Get("X-MCPGate-Token")
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}
	return tok != "" && subtle.ConstantTimeCompare([]byte(tok), []byte(s.Token)) == 1
}

func (s *Server) handleGet(w http.ResponseWriter) {
	c, err := config.Load(s.ConfigPath)
	if errors.Is(err, os.ErrNotExist) {
		c = config.Default() // a config that hasn't been created yet → show defaults
	} else if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(c)
}

func (s *Server) handlePost(w http.ResponseWriter, r *http.Request) {
	var c config.Config
	if err := json.NewDecoder(r.Body).Decode(&c); err != nil {
		http.Error(w, "bad json: "+err.Error(), http.StatusBadRequest)
		return
	}
	data, err := json.MarshalIndent(&c, "", "  ")
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if err := os.WriteFile(s.ConfigPath, append(data, '\n'), 0o644); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// localHost reports whether a Host/Origin host is a loopback name.
func localHost(host string) bool {
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host
	}
	switch h {
	case "127.0.0.1", "localhost", "::1", "":
		return true
	}
	return false
}

// sameOrigin reports whether a write request originates from our own page.
func sameOrigin(r *http.Request) bool {
	o := r.Header.Get("Origin")
	if o == "" {
		// Browsers may omit Origin on same-origin requests; trust Sec-Fetch-Site.
		return r.Header.Get("Sec-Fetch-Site") == "same-origin"
	}
	u, err := url.Parse(o)
	if err != nil {
		return false
	}
	return localHost(u.Host)
}

const page = `<!doctype html>
<html><head><meta charset="utf-8"><title>mcpgate config</title>
<style>
:root{--bg:#0e1116;--card:#171b22;--muted:#8b949e;--accent:#58a6ff;--ok:#3fb950;--err:#f85149;--text:#e6edf3;--line:#262c36}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:12px 18px;display:flex;align-items:center;gap:14px}
h1{font-size:15px;margin:0;font-weight:600}
.muted{color:var(--muted)}
main{padding:16px 18px 60px;max-width:760px}
section{background:var(--card);border:1px solid var(--line);border-radius:8px;padding:14px 16px;margin:12px 0}
h2{font-size:13px;text-transform:uppercase;letter-spacing:.04em;color:var(--muted);margin:0 0 10px}
label{display:block;margin:10px 0 4px;font-size:13px;color:var(--muted)}
input[type=text],input[type=number],select,textarea{width:100%;background:#0b0e13;color:var(--text);border:1px solid var(--line);border-radius:6px;padding:7px 9px;font:13px ui-monospace,Menlo,monospace}
textarea{min-height:70px;resize:vertical}
.row{display:flex;gap:12px}.row>div{flex:1}
.chk{display:flex;align-items:center;gap:8px;color:var(--text)}
button{background:var(--accent);color:#04101f;border:0;border-radius:6px;padding:8px 16px;font-weight:600;cursor:pointer}
#status{margin-left:auto;font-size:13px}
.hint{font-size:12px;color:var(--muted);margin-top:4px}
</style></head>
<body>
<header>
  <h1>mcpgate <span class="muted">config</span></h1>
  <span id="status" class="muted">loading…</span>
</header>
<main>
  <section>
    <h2>Redaction (ingress filter)</h2>
    <div class="row">
      <div><label>backend</label><select id="redact"><option>builtin</option><option>gliner</option><option>off</option></select></div>
      <div><label>threshold</label><input id="threshold" type="number" step="0.05" min="0" max="1"></div>
    </div>
    <label>gliner sidecar URL</label><input id="redactUrl" type="text">
  </section>
  <section>
    <h2>Gate</h2>
    <label class="chk"><input id="allowActions" type="checkbox"> allow action tools without a per-tool grant <span class="muted">(off = deny-by-default)</span></label>
    <label>read tools <span class="muted">— results filtered, calls flow</span></label>
    <input id="readTools" type="text" placeholder="read_email, search_inbox">
    <label>action tools <span class="muted">— calls gated</span></label>
    <input id="actionTools" type="text" placeholder="send_email, delete_email">
    <label>gated tools <span class="muted">— require approval (denied for now)</span></label>
    <input id="gatedTools" type="text" placeholder="wire_money">
    <p class="hint">Comma-separated. Unknown tools are treated as actions (deny-by-default).</p>
  </section>
  <section>
    <h2>Argument allowlists</h2>
    <label>one <code>tool=glob,glob</code> per line</label>
    <textarea id="argAllow" placeholder="send_email=*@yourcompany.com&#10;post_webhook=https://hooks.acme.com/*"></textarea>
    <p class="hint">The tool is permitted only if every recipient/URL in its arguments matches a glob.</p>
  </section>
  <section>
    <h2>Audit</h2>
    <label>audit file (JSONL, appended)</label><input id="auditFile" type="text" placeholder="~/.local/share/mcpgate/audit.jsonl">
  </section>
  <div style="display:flex;align-items:center;gap:14px">
    <button id="save">Save</button>
    <span class="hint">Changes apply the next time the client launches the wrapped server.</span>
  </div>
</main>
<script>
const $ = s => document.querySelector(s);
const token = new URLSearchParams(location.search).get('token') || '';
const hdr = {'X-MCPGate-Token': token};
function status(msg, kind){ const s=$('#status'); s.textContent=msg; s.style.color = kind==='err'?'var(--err)':kind==='ok'?'var(--ok)':'var(--muted)'; }
function list(id){ return $('#'+id).value.split(',').map(s=>s.trim()).filter(Boolean); }
function parseAllow(t){ const m={}; t.split('\n').forEach(l=>{ l=l.trim(); if(!l)return; const i=l.indexOf('='); if(i<1)return; const tool=l.slice(0,i).trim(); const g=l.slice(i+1).split(',').map(s=>s.trim()).filter(Boolean); if(tool&&g.length)m[tool]=g; }); return m; }
async function load(){
  try{
    const r = await fetch('/config',{headers:hdr});
    if(!r.ok){ status('cannot load config ('+r.status+') — open the URL printed by mcpgate, with ?token=', 'err'); return; }
    const c = await r.json();
    $('#redact').value=c.redact||'builtin'; $('#threshold').value=c.threshold??0.5; $('#redactUrl').value=c.redactUrl||'';
    $('#allowActions').checked=!!c.allowActions;
    $('#readTools').value=(c.readTools||[]).join(', '); $('#actionTools').value=(c.actionTools||[]).join(', '); $('#gatedTools').value=(c.gatedTools||[]).join(', ');
    $('#auditFile').value=c.auditFile||'';
    $('#argAllow').value=Object.entries(c.argAllow||{}).map(e=>e[0]+'='+e[1].join(',')).join('\n');
    status('loaded', '');
  }catch(e){ status('load error: '+e, 'err'); }
}
async function save(){
  const c = {
    redact:$('#redact').value, redactUrl:$('#redactUrl').value, threshold:parseFloat($('#threshold').value)||0.5,
    allowActions:$('#allowActions').checked,
    readTools:list('readTools'), actionTools:list('actionTools'), gatedTools:list('gatedTools'),
    argAllow:parseAllow($('#argAllow').value), auditFile:$('#auditFile').value
  };
  try{
    const r = await fetch('/config',{method:'POST',headers:Object.assign({'Content-Type':'application/json'},hdr),body:JSON.stringify(c)});
    if(r.ok) status('saved ✓ — restart the server/agent to apply', 'ok');
    else status('save failed ('+r.status+'): '+(await r.text()), 'err');
  }catch(e){ status('save error: '+e, 'err'); }
}
$('#save').addEventListener('click', save);
load();
</script>
</body></html>`
