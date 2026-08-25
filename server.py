"""Skill Server — serves SKILL.md files with a dashboard UI and token auth."""
import hashlib
import hmac
import json
import os
import secrets
import subprocess
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response, Depends, Cookie
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
import uvicorn
import yaml
import markdown

app = FastAPI(title="Devin's Skill Server")

REPO_URL = os.environ.get("REPO_URL", "https://github.com/DevinWalker/agent-skills.git")
REPO_DIR = Path("/data/skills")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
GH_TOKEN = os.environ.get("GH_TOKEN", "")
API_TOKEN = os.environ.get("API_TOKEN", "")  # Required for all access

# Session tokens for browser auth (login form sets a cookie)
active_sessions: set[str] = set()

# Track sync events
sync_log: list[dict] = []
last_sync: dict = {"time": None, "status": None, "commit": None}

bearer_scheme = HTTPBearer(auto_error=False)


def verify_token(token: str) -> bool:
    """Constant-time comparison of a token against API_TOKEN."""
    if not API_TOKEN:
        return True  # No token configured = open (dev mode)
    return secrets.compare_digest(token, API_TOKEN)


def require_auth(request: Request):
    """Check auth via Bearer token OR session cookie. Raise 401/403 on failure."""
    # 1. Bearer token (for agents / API clients)
    auth_header = request.headers.get("authorization", "")
    if auth_header.startswith("Bearer "):
        token = auth_header[7:]
        if verify_token(token):
            return True
        raise HTTPException(403, "Invalid token")

    # 2. Session cookie (for browser dashboard)
    session = request.cookies.get("skill_session")
    if session and session in active_sessions:
        return True

    # 3. Query param (for simple curl usage)
    token = request.query_params.get("token", "")
    if token and verify_token(token):
        return True

    raise HTTPException(401, "Authentication required")


def clone_or_pull():
    """Clone repo if missing, otherwise pull latest."""
    global last_sync
    try:
        if not REPO_DIR.exists():
            REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
            url = REPO_URL
            if GH_TOKEN and "github.com" in url:
                url = url.replace("https://", f"https://x-access-token:{GH_TOKEN}@")
            subprocess.run(["git", "clone", url, str(REPO_DIR)], check=True, capture_output=True)
        else:
            subprocess.run(["git", "-C", str(REPO_DIR), "pull", "--ff-only"],
                           check=True, capture_output=True)

        result = subprocess.run(
            ["git", "-C", str(REPO_DIR), "log", "-1", "--format=%H|%s|%ai"],
            capture_output=True, text=True
        )
        parts = result.stdout.strip().split("|", 2)
        commit_info = {
            "sha": parts[0][:8] if parts else "unknown",
            "message": parts[1] if len(parts) > 1 else "",
            "date": parts[2] if len(parts) > 2 else "",
        }

        now = datetime.now(timezone.utc).isoformat()
        last_sync = {"time": now, "status": "ok", "commit": commit_info}
        sync_log.append({"time": now, "status": "ok", "commit": commit_info["sha"]})
        if len(sync_log) > 50:
            sync_log.pop(0)

    except Exception as e:
        now = datetime.now(timezone.utc).isoformat()
        last_sync = {"time": now, "status": f"error: {e}", "commit": None}
        sync_log.append({"time": now, "status": "error", "detail": str(e)})


def find_skills():
    """Walk the repo and find all SKILL.md files."""
    skills = []
    for skill_md in sorted(REPO_DIR.rglob("SKILL.md")):
        rel = skill_md.relative_to(REPO_DIR)
        skill_dir = rel.parent

        content = skill_md.read_text(encoding="utf-8")
        meta = {"name": str(skill_dir), "description": ""}
        if content.startswith("---"):
            parts = content.split("---", 2)
            if len(parts) >= 3:
                try:
                    fm = yaml.safe_load(parts[1])
                    if isinstance(fm, dict):
                        meta.update(fm)
                except Exception:
                    pass

        category = str(skill_dir).split("/")[0] if "/" in str(skill_dir) else "uncategorized"

        refs_dir = skill_md.parent / "references"
        refs = []
        if refs_dir.is_dir():
            refs = [str(f.relative_to(skill_md.parent)) for f in sorted(refs_dir.rglob("*")) if f.is_file()]

        all_files = [str(f.relative_to(skill_md.parent))
                     for f in sorted(skill_md.parent.rglob("*"))
                     if f.is_file() and ".git" not in str(f)]

        body = content.split("---", 2)[2] if content.startswith("---") and content.count("---") >= 2 else content
        word_count = len(body.split())

        skills.append({
            "name": meta.get("name", str(skill_dir)),
            "description": meta.get("description", ""),
            "path": str(skill_dir),
            "category": category,
            "word_count": word_count,
            "file_count": len(all_files),
            "files": {
                "skill_md": str(rel),
                "references": refs,
                "all": all_files,
            }
        })
    return skills


def render_markdown(text: str) -> str:
    """Render markdown to HTML, stripping frontmatter."""
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            text = parts[2]
    return markdown.markdown(text, extensions=["tables", "fenced_code", "codehilite"])


# --- Login page (no auth required) ---

LOGIN_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Login — Skill Server</title>
<style>
  :root { --bg: #0d1117; --surface: #161b22; --border: #30363d;
          --text: #e6edf3; --accent: #58a6ff; --red: #f85149; }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: var(--bg); color: var(--text); display: flex;
         align-items: center; justify-content: center; min-height: 100vh; }
  .card { background: var(--surface); border: 1px solid var(--border);
          border-radius: 12px; padding: 32px; width: 100%; max-width: 380px; }
  h1 { font-size: 20px; margin-bottom: 8px; }
  p { font-size: 13px; color: #8b949e; margin-bottom: 20px; }
  input { width: 100%; padding: 10px 14px; border: 1px solid var(--border);
          border-radius: 6px; background: var(--bg); color: var(--text);
          font-size: 14px; margin-bottom: 12px; outline: none; }
  input:focus { border-color: var(--accent); }
  button { width: 100%; padding: 10px; background: var(--accent); border: none;
           border-radius: 6px; color: #fff; font-size: 14px; font-weight: 600;
           cursor: pointer; }
  button:hover { opacity: 0.9; }
  .err { color: var(--red); font-size: 13px; margin-bottom: 12px; display: none; }
</style>
</head>
<body>
<div class="card">
  <h1>⚡ Skill Server</h1>
  <p>Enter your API token to access the dashboard.</p>
  <div class="err" id="err">Invalid token. Try again.</div>
  <form method="POST" action="/login">
    <input type="password" name="token" placeholder="API token" autofocus required>
    <button type="submit">Sign in</button>
  </form>
</div>
<script>
  if (location.search.includes('error=1'))
    document.getElementById('err').style.display = 'block';
</script>
</body>
</html>"""


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Skill Server — Devin Walker</title>
<style>
  :root {
    --bg: #0d1117; --surface: #161b22; --border: #30363d;
    --text: #e6edf3; --text-muted: #8b949e; --accent: #58a6ff;
    --green: #3fb950; --orange: #d29922; --red: #f85149;
    --tag-bg: #1f2937; --tag-text: #9ca3af;
  }
  * { box-sizing: border-box; margin: 0; padding: 0; }
  body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
         background: var(--bg); color: var(--text); line-height: 1.6; }

  .container { max-width: 960px; margin: 0 auto; padding: 24px; }

  header { display: flex; align-items: center; justify-content: space-between;
           padding: 20px 0; border-bottom: 1px solid var(--border); margin-bottom: 24px; }
  header h1 { font-size: 22px; font-weight: 600; }
  header h1 span { color: var(--accent); }
  .logout { font-size: 13px; color: var(--text-muted); text-decoration: none;
            border: 1px solid var(--border); padding: 4px 12px; border-radius: 6px; }
  .logout:hover { color: var(--text); border-color: var(--text-muted); }

  .sync-bar { display: flex; align-items: center; gap: 12px;
              background: var(--surface); border: 1px solid var(--border);
              border-radius: 8px; padding: 12px 16px; margin-bottom: 24px; font-size: 14px; }
  .sync-dot { width: 8px; height: 8px; border-radius: 50%; flex-shrink: 0; }
  .sync-dot.ok { background: var(--green); }
  .sync-dot.error { background: var(--red); }
  .sync-dot.unknown { background: var(--orange); }
  .sync-info { flex: 1; }
  .sync-info .commit { color: var(--accent); font-family: monospace; font-size: 13px; }
  .sync-info .time { color: var(--text-muted); font-size: 12px; margin-left: 8px; }
  .sync-btn { background: var(--surface); border: 1px solid var(--border);
              color: var(--accent); padding: 6px 14px; border-radius: 6px;
              cursor: pointer; font-size: 13px; }
  .sync-btn:hover { background: var(--border); }

  .stats { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
           gap: 12px; margin-bottom: 24px; }
  .stat { background: var(--surface); border: 1px solid var(--border);
          border-radius: 8px; padding: 16px; text-align: center; }
  .stat .num { font-size: 28px; font-weight: 700; color: var(--accent); }
  .stat .label { font-size: 12px; color: var(--text-muted); text-transform: uppercase;
                 letter-spacing: 0.5px; margin-top: 4px; }

  .skill-grid { display: grid; gap: 12px; }
  .skill-card { background: var(--surface); border: 1px solid var(--border);
                border-radius: 8px; padding: 16px; cursor: pointer;
                transition: border-color 0.15s; }
  .skill-card:hover { border-color: var(--accent); }
  .skill-card .top { display: flex; align-items: start; justify-content: space-between; }
  .skill-card h3 { font-size: 16px; font-weight: 600; margin-bottom: 6px; }
  .skill-card .desc { color: var(--text-muted); font-size: 13px;
                       display: -webkit-box; -webkit-line-clamp: 2;
                       -webkit-box-orient: vertical; overflow: hidden; }
  .skill-card .meta { display: flex; gap: 12px; margin-top: 10px; font-size: 12px; color: var(--text-muted); }
  .tag { background: var(--tag-bg); color: var(--tag-text); padding: 2px 8px;
         border-radius: 4px; font-size: 11px; text-transform: uppercase; letter-spacing: 0.3px; }

  .modal-overlay { position: fixed; top: 0; left: 0; right: 0; bottom: 0;
                   background: rgba(0,0,0,0.7); display: none; z-index: 100;
                   justify-content: center; align-items: start; padding: 40px 20px;
                   overflow-y: auto; }
  .modal-overlay.open { display: flex; }
  .modal { background: var(--surface); border: 1px solid var(--border);
           border-radius: 12px; width: 100%; max-width: 800px; overflow: hidden; }
  .modal-header { display: flex; justify-content: space-between; align-items: center;
                  padding: 16px 20px; border-bottom: 1px solid var(--border); }
  .modal-header h2 { font-size: 18px; }
  .modal-close { background: none; border: none; color: var(--text-muted);
                 font-size: 24px; cursor: pointer; padding: 4px 8px; }
  .modal-close:hover { color: var(--text); }
  .modal-tabs { display: flex; border-bottom: 1px solid var(--border); padding: 0 20px; }
  .modal-tab { padding: 10px 16px; font-size: 13px; color: var(--text-muted);
               cursor: pointer; border-bottom: 2px solid transparent; margin-bottom: -1px; }
  .modal-tab.active { color: var(--accent); border-bottom-color: var(--accent); }
  .modal-body { padding: 20px; max-height: 70vh; overflow-y: auto; }
  .modal-body .rendered { font-size: 14px; line-height: 1.7; }
  .modal-body .rendered h1 { font-size: 20px; margin: 20px 0 10px; }
  .modal-body .rendered h2 { font-size: 17px; margin: 18px 0 8px; color: var(--accent); }
  .modal-body .rendered h3 { font-size: 15px; margin: 14px 0 6px; }
  .modal-body .rendered p { margin: 8px 0; }
  .modal-body .rendered ul, .modal-body .rendered ol { margin: 8px 0; padding-left: 24px; }
  .modal-body .rendered li { margin: 4px 0; }
  .modal-body .rendered code { background: var(--bg); padding: 2px 6px; border-radius: 4px;
                                font-size: 13px; font-family: 'SF Mono', monospace; }
  .modal-body .rendered pre { background: var(--bg); padding: 14px; border-radius: 6px;
                               overflow-x: auto; margin: 10px 0; }
  .modal-body .rendered pre code { background: none; padding: 0; }
  .modal-body .rendered blockquote { border-left: 3px solid var(--accent); padding-left: 14px;
                                      color: var(--text-muted); margin: 10px 0; }
  .modal-body .rendered table { border-collapse: collapse; width: 100%; margin: 10px 0; }
  .modal-body .rendered th, .modal-body .rendered td {
    border: 1px solid var(--border); padding: 8px 12px; text-align: left; font-size: 13px; }
  .modal-body .rendered th { background: var(--bg); }
  .modal-body .rendered strong { color: var(--text); }
  .modal-body .raw { white-space: pre-wrap; font-family: 'SF Mono', monospace;
                     font-size: 13px; color: var(--text-muted); }
  .file-list { list-style: none; }
  .file-list li { padding: 6px 0; border-bottom: 1px solid var(--border); font-size: 13px; }
  .file-list li:last-child { border: none; }
  .file-list a { color: var(--accent); text-decoration: none; }
  .file-list a:hover { text-decoration: underline; }

  .copy-url { display: flex; align-items: center; gap: 8px; margin-top: 12px;
              background: var(--bg); border: 1px solid var(--border); border-radius: 6px;
              padding: 8px 12px; font-size: 12px; }
  .copy-url code { flex: 1; color: var(--text-muted); font-family: monospace; word-break: break-all; }
  .copy-url button { background: var(--border); border: none; color: var(--text);
                     padding: 4px 10px; border-radius: 4px; cursor: pointer; font-size: 12px; }

  .log-list { font-size: 13px; font-family: monospace; }
  .log-list .entry { padding: 6px 0; border-bottom: 1px solid var(--border);
                     display: flex; gap: 12px; }
  .log-list .entry:last-child { border: none; }
  .log-ok { color: var(--green); }
  .log-error { color: var(--red); }
</style>
</head>
<body>
<div class="container">
  <header>
    <h1><span>⚡</span> Skill Server</h1>
    <a href="/logout" class="logout">Sign out</a>
  </header>

  <div class="sync-bar" id="syncBar">
    <div class="sync-dot unknown" id="syncDot"></div>
    <div class="sync-info" id="syncInfo">Loading...</div>
    <button class="sync-btn" onclick="doSync()">↻ Sync now</button>
    <button class="sync-btn" onclick="showLog()">Log</button>
  </div>

  <div class="stats" id="stats"></div>
  <div class="skill-grid" id="skillGrid"></div>
</div>

<div class="modal-overlay" id="modal" onclick="if(event.target===this)closeModal()">
  <div class="modal">
    <div class="modal-header">
      <h2 id="modalTitle"></h2>
      <button class="modal-close" onclick="closeModal()">×</button>
    </div>
    <div class="modal-tabs" id="modalTabs"></div>
    <div class="modal-body" id="modalBody"></div>
  </div>
</div>

<script>
const BASE = location.origin;
let skillData = [];

async function load() {
  const r = await fetch('/api/dashboard');
  if (r.status === 401) { location.href = '/login'; return; }
  const d = await r.json();
  skillData = d.skills;
  renderStats(d);
  renderSync(d.sync);
  renderGrid(d.skills);
}

function renderStats(d) {
  const cats = [...new Set(d.skills.map(s => s.category))];
  const totalWords = d.skills.reduce((a, s) => a + s.word_count, 0);
  const totalFiles = d.skills.reduce((a, s) => a + s.file_count, 0);
  document.getElementById('stats').innerHTML = `
    <div class="stat"><div class="num">${d.skills.length}</div><div class="label">Skills</div></div>
    <div class="stat"><div class="num">${cats.length}</div><div class="label">Categories</div></div>
    <div class="stat"><div class="num">${totalFiles}</div><div class="label">Files</div></div>
    <div class="stat"><div class="num">${(totalWords/1000).toFixed(1)}k</div><div class="label">Words</div></div>
  `;
}

function renderSync(sync) {
  const dot = document.getElementById('syncDot');
  const info = document.getElementById('syncInfo');
  if (!sync.time) { info.textContent = 'Not synced yet'; return; }
  const status = sync.status === 'ok' ? 'ok' : 'error';
  dot.className = 'sync-dot ' + status;
  const ago = timeAgo(sync.time);
  let html = '';
  if (sync.commit) {
    html = `<span class="commit">${sync.commit.sha}</span> ${sync.commit.message} <span class="time">${ago}</span>`;
  } else {
    html = `<span style="color:var(--red)">${sync.status}</span> <span class="time">${ago}</span>`;
  }
  info.innerHTML = html;
}

function renderGrid(skills) {
  document.getElementById('skillGrid').innerHTML = skills.map(s => `
    <div class="skill-card" onclick="openSkill('${s.path}')">
      <div class="top">
        <h3>${s.name}</h3>
        <span class="tag">${s.category}</span>
      </div>
      <div class="desc">${esc(s.description)}</div>
      <div class="meta">
        <span>📄 ${s.file_count} files</span>
        <span>📝 ${s.word_count.toLocaleString()} words</span>
        <span>📚 ${s.files.references.length} refs</span>
      </div>
    </div>
  `).join('');
}

async function openSkill(path) {
  const skill = skillData.find(s => s.path === path);
  if (!skill) return;

  document.getElementById('modalTitle').textContent = skill.name;

  const tabs = [{id: 'rendered', label: 'Rendered'}, {id: 'raw', label: 'Raw'}];
  skill.files.references.forEach(r => {
    const name = r.split('/').pop().replace('.md','');
    tabs.push({id: r, label: name});
  });

  document.getElementById('modalTabs').innerHTML = tabs.map((t, i) =>
    `<div class="modal-tab ${i===0?'active':''}" onclick="switchTab('${t.id}','${path}')">${t.label}</div>`
  ).join('');

  await switchTab('rendered', path);
  document.getElementById('modal').classList.add('open');
}

async function switchTab(tabId, path) {
  document.querySelectorAll('.modal-tab').forEach(t =>
    t.classList.toggle('active', t.textContent === tabId ||
      t.getAttribute('onclick').includes("'"+tabId+"'"))
  );

  const body = document.getElementById('modalBody');
  const skill = skillData.find(s => s.path === path);

  if (tabId === 'rendered') {
    const r = await fetch(`/api/skill/${path}/rendered`);
    const d = await r.json();
    body.innerHTML = `
      <div class="rendered">${d.html}</div>
      <div class="copy-url">
        <code>${BASE}/${path}</code>
        <button onclick="navigator.clipboard.writeText('${BASE}/${path}')">Copy URL</button>
      </div>
      <h3 style="margin-top:16px; font-size:14px; color:var(--text-muted)">Files</h3>
      <ul class="file-list">
        ${skill.files.all.map(f => `<li><a href="/${path}/${f}" target="_blank">${f}</a></li>`).join('')}
      </ul>
    `;
  } else if (tabId === 'raw') {
    const r = await fetch(`/${path}`);
    const text = await r.text();
    body.innerHTML = `<div class="raw">${esc(text)}</div>`;
  } else {
    const r = await fetch(`/${path}/${tabId}`);
    const text = await r.text();
    const rr = await fetch(`/api/render`, {method:'POST', headers:{'Content-Type':'application/json'}, body: JSON.stringify({text})});
    const d = await rr.json();
    body.innerHTML = `<div class="rendered">${d.html}</div>`;
  }
}

function closeModal() { document.getElementById('modal').classList.remove('open'); }

async function doSync() {
  document.getElementById('syncInfo').textContent = 'Syncing...';
  await fetch('/api/sync', {method: 'POST'});
  setTimeout(load, 2000);
}

async function showLog() {
  const r = await fetch('/api/sync-log');
  const d = await r.json();
  document.getElementById('modalTitle').textContent = 'Sync Log';
  document.getElementById('modalTabs').innerHTML = '';
  document.getElementById('modalBody').innerHTML = `
    <div class="log-list">
      ${d.log.reverse().map(e => `
        <div class="entry">
          <span class="${e.status==='ok'?'log-ok':'log-error'}">●</span>
          <span>${new Date(e.time).toLocaleString()}</span>
          <span>${e.commit || e.detail || e.status}</span>
        </div>
      `).join('')}
    </div>
  `;
  document.getElementById('modal').classList.add('open');
}

function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
function timeAgo(iso) {
  const s = Math.floor((Date.now() - new Date(iso).getTime()) / 1000);
  if (s < 60) return 'just now';
  if (s < 3600) return Math.floor(s/60) + 'm ago';
  if (s < 86400) return Math.floor(s/3600) + 'h ago';
  return Math.floor(s/86400) + 'd ago';
}

document.addEventListener('keydown', e => { if (e.key === 'Escape') closeModal(); });
load();
</script>
</body>
</html>"""


# --- Public routes (no auth) ---

@app.on_event("startup")
def startup():
    clone_or_pull()


@app.get("/login", response_class=HTMLResponse)
def login_page():
    return LOGIN_HTML


@app.post("/login")
async def login_submit(request: Request):
    form = await request.form()
    token = form.get("token", "")
    if not verify_token(token):
        return RedirectResponse("/login?error=1", status_code=303)

    session_id = secrets.token_urlsafe(32)
    active_sessions.add(session_id)
    # Cap sessions to prevent memory leak
    if len(active_sessions) > 100:
        active_sessions.pop()

    response = RedirectResponse("/", status_code=303)
    response.set_cookie("skill_session", session_id, httponly=True, secure=True,
                        samesite="lax", max_age=86400 * 7)
    return response


@app.get("/logout")
def logout(request: Request):
    session = request.cookies.get("skill_session")
    if session:
        active_sessions.discard(session)
    response = RedirectResponse("/login", status_code=303)
    response.delete_cookie("skill_session")
    return response


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/webhook")
async def webhook(request: Request):
    """GitHub push webhook — authenticated by HMAC, not bearer token."""
    body = await request.body()

    if WEBHOOK_SECRET:
        sig = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(403, "Invalid signature")

    def do_pull():
        try:
            clone_or_pull()
        except Exception as e:
            print(f"Pull failed: {e}")

    threading.Thread(target=do_pull, daemon=True).start()
    return {"status": "pulling"}


# --- Protected routes (require auth) ---

@app.get("/", response_class=HTMLResponse)
def dashboard(request: Request):
    try:
        require_auth(request)
    except HTTPException:
        return RedirectResponse("/login", status_code=303)
    return DASHBOARD_HTML


@app.get("/api/dashboard", response_class=JSONResponse)
def api_dashboard(request: Request):
    require_auth(request)
    return {"skills": find_skills(), "sync": last_sync, "repo": REPO_URL}


@app.get("/api/skill/{path:path}/rendered", response_class=JSONResponse)
def api_skill_rendered(path: str, request: Request):
    require_auth(request)
    file_path = REPO_DIR / path / "SKILL.md"
    if not file_path.is_file():
        raise HTTPException(404)
    content = file_path.read_text(encoding="utf-8")
    return {"html": render_markdown(content)}


@app.post("/api/render", response_class=JSONResponse)
async def api_render(request: Request):
    require_auth(request)
    data = await request.json()
    return {"html": render_markdown(data.get("text", ""))}


@app.post("/api/sync")
def api_sync(request: Request):
    require_auth(request)
    clone_or_pull()
    return {"status": "synced", "sync": last_sync}


@app.get("/api/sync-log", response_class=JSONResponse)
def api_sync_log(request: Request):
    require_auth(request)
    return {"log": list(sync_log)}


@app.get("/catalog", response_class=JSONResponse)
def catalog(request: Request):
    require_auth(request)
    return {"skills": find_skills()}


@app.get("/{path:path}")
def serve_file(path: str, request: Request):
    require_auth(request)
    file_path = REPO_DIR / path

    if file_path.is_dir():
        file_path = file_path / "SKILL.md"

    if not file_path.is_file():
        raise HTTPException(404, f"Not found: {path}")

    try:
        file_path.resolve().relative_to(REPO_DIR.resolve())
    except ValueError:
        raise HTTPException(403, "Forbidden")

    content = file_path.read_text(encoding="utf-8")
    suffix = file_path.suffix.lower()
    ct = {
        ".md": "text/markdown; charset=utf-8",
        ".yaml": "text/yaml; charset=utf-8",
        ".yml": "text/yaml; charset=utf-8",
        ".json": "application/json",
        ".txt": "text/plain; charset=utf-8",
    }.get(suffix, "text/plain; charset=utf-8")

    return Response(content=content, media_type=ct)


if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
