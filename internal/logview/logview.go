// Package logview is a read-only, localhost viewer for the audit JSONL file.
// It is deliberately decoupled from the proxy: the proxy writes the file, this
// reads it — so the UI is optional, can't affect enforcement, and holds no
// state. Bind it to 127.0.0.1 only; the log contains attacker payloads and tool
// metadata that should never leave the machine.
package logview

import (
	"encoding/json"
	"io"
	"net/http"
	"os"
	"strings"
)

type Server struct {
	AuditFile string // JSONL file to tail
	MaxLines  int    // most-recent lines to serve (0 → 2000)
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet { // read-only
		http.Error(w, "read-only", http.StatusMethodNotAllowed)
		return
	}
	switch r.URL.Path {
	case "/":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		io.WriteString(w, page)
	case "/events":
		s.handleEvents(w)
	default:
		http.NotFound(w, r)
	}
}

// handleEvents returns the most-recent valid JSONL lines as a JSON array.
func (s *Server) handleEvents(w http.ResponseWriter) {
	w.Header().Set("Content-Type", "application/json")
	data, err := os.ReadFile(s.AuditFile)
	if err != nil {
		io.WriteString(w, "[]") // file may not exist yet
		return
	}
	var valid []string
	for _, ln := range strings.Split(string(data), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" && json.Valid([]byte(ln)) {
			valid = append(valid, ln)
		}
	}
	max := s.MaxLines
	if max <= 0 {
		max = 2000
	}
	if len(valid) > max {
		valid = valid[len(valid)-max:]
	}
	io.WriteString(w, "["+strings.Join(valid, ",")+"]")
}

const page = `<!doctype html>
<html><head><meta charset="utf-8"><title>mcpgate audit</title>
<style>
:root{--bg:#0e1116;--card:#171b22;--muted:#8b949e;--warn:#f0883e;--warnbg:#3d2a12;--ok:#3fb950;--text:#e6edf3;--line:#262c36}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);font:14px/1.5 -apple-system,Segoe UI,Roboto,sans-serif}
header{position:sticky;top:0;background:var(--bg);border-bottom:1px solid var(--line);padding:12px 18px;display:flex;align-items:center;gap:14px}
h1{font-size:15px;margin:0;font-weight:600}
.muted{color:var(--muted)}
.dot{width:8px;height:8px;border-radius:50%;background:var(--ok);display:inline-block;animation:p 2s infinite}
@keyframes p{0%,100%{opacity:1}50%{opacity:.3}}
label.t{margin-left:auto;color:var(--muted);font-size:13px;cursor:pointer;user-select:none}
main{padding:12px 18px 48px;max-width:1000px}
.ev{border:1px solid var(--line);border-left:3px solid var(--line);background:var(--card);border-radius:6px;padding:8px 12px;margin:8px 0}
.ev.warn{border-left-color:var(--warn)}
.top{display:flex;gap:10px;align-items:baseline}
.badge{font-size:11px;font-weight:600;padding:1px 6px;border-radius:4px}
.badge.warn{background:var(--warnbg);color:var(--warn)}
.badge.info{background:#1f2530;color:var(--muted)}
.msg{font-weight:600}
.fields{color:var(--muted);font-size:13px;margin-left:auto}
.time{color:var(--muted);font-size:12px;margin-left:10px}
.payload{margin-top:6px;font-family:ui-monospace,Menlo,monospace;font-size:12.5px;background:#0b0e13;border:1px solid var(--line);border-radius:4px;padding:6px 8px;white-space:pre-wrap;color:#f0d9b5}
.empty{color:var(--muted);text-align:center;padding:48px}
</style></head>
<body>
<header>
  <span class="dot"></span>
  <h1>mcpgate <span class="muted">audit</span></h1>
  <span id="count" class="muted"></span>
  <label class="t"><input type="checkbox" id="flagged"> flagged only</label>
</header>
<main id="list"><div class="empty">waiting for events…</div></main>
<script>
const $ = s => document.querySelector(s);
const esc = s => String(s).replace(/[&<>]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;'}[c]));
const fmtTime = t => { try { return new Date(t).toLocaleTimeString(); } catch(e){ return t||''; } };
function fields(e){
  const skip = new Set(['time','level','msg','text']);
  return Object.keys(e).filter(k=>!skip.has(k)).map(k=>k+'='+e[k]).join('  ');
}
function render(events){
  const only = $('#flagged').checked;
  const rows = events.filter(e => !only || e.level==='WARN').reverse();
  $('#count').textContent = events.length+' events'+(only?' ('+rows.length+' flagged)':'');
  if(!rows.length){ $('#list').innerHTML = '<div class="empty">no '+(only?'flagged ':'')+'events yet</div>'; return; }
  $('#list').innerHTML = rows.map(e => {
    const warn = e.level==='WARN';
    const payload = e.text ? '<div class="payload">'+esc(e.text)+'</div>' : '';
    return '<div class="ev '+(warn?'warn':'')+'"><div class="top">'
      + '<span class="badge '+(warn?'warn':'info')+'">'+esc(e.level||'')+'</span>'
      + '<span class="msg">'+esc(e.msg||'')+'</span>'
      + '<span class="fields">'+esc(fields(e))+'</span>'
      + '<span class="time">'+fmtTime(e.time)+'</span>'
      + '</div>'+payload+'</div>';
  }).join('');
}
async function load(){ try { const r = await fetch('/events'); render(await r.json()); } catch(e){} }
$('#flagged').addEventListener('change', load);
load(); setInterval(load, 2000);
</script>
</body></html>`
