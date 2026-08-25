"""Skill Server — serves SKILL.md files from a git repo over HTTPS."""
import hashlib
import hmac
import json
import os
import subprocess
import threading
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import PlainTextResponse, JSONResponse
import uvicorn
import yaml

app = FastAPI(title="Devin's Skill Server")

REPO_URL = os.environ.get("REPO_URL", "https://github.com/DevinWalker/agent-skills.git")
REPO_DIR = Path("/data/skills")
WEBHOOK_SECRET = os.environ.get("WEBHOOK_SECRET", "")
GH_TOKEN = os.environ.get("GH_TOKEN", "")

def clone_or_pull():
    """Clone repo if missing, otherwise pull latest."""
    if not REPO_DIR.exists():
        REPO_DIR.parent.mkdir(parents=True, exist_ok=True)
        url = REPO_URL
        if GH_TOKEN and "github.com" in url:
            url = url.replace("https://", f"https://x-access-token:{GH_TOKEN}@")
        subprocess.run(["git", "clone", url, str(REPO_DIR)], check=True, capture_output=True)
    else:
        subprocess.run(["git", "-C", str(REPO_DIR), "pull", "--ff-only"],
                       check=True, capture_output=True)

def find_skills():
    """Walk the repo and find all SKILL.md files."""
    skills = []
    for skill_md in sorted(REPO_DIR.rglob("SKILL.md")):
        rel = skill_md.relative_to(REPO_DIR)
        skill_dir = rel.parent

        # Parse frontmatter
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

        # List reference files
        refs_dir = skill_md.parent / "references"
        refs = []
        if refs_dir.is_dir():
            refs = [str(f.relative_to(skill_md.parent)) for f in sorted(refs_dir.rglob("*")) if f.is_file()]

        skills.append({
            "name": meta.get("name", str(skill_dir)),
            "description": meta.get("description", ""),
            "path": str(skill_dir),
            "files": {
                "skill_md": str(rel),
                "references": refs,
            }
        })
    return skills

# --- Routes ---

@app.on_event("startup")
def startup():
    clone_or_pull()

@app.get("/", response_class=JSONResponse)
def index():
    """Catalog of all skills."""
    return {"skills": find_skills(), "repo": REPO_URL}

@app.get("/catalog", response_class=JSONResponse)
def catalog():
    """Alias for index."""
    return {"skills": find_skills()}

@app.get("/health")
def health():
    return {"status": "ok"}

@app.get("/{path:path}")
def serve_file(path: str):
    """Serve any file from the repo."""
    file_path = REPO_DIR / path

    # If path points to a directory, try SKILL.md inside it
    if file_path.is_dir():
        file_path = file_path / "SKILL.md"

    if not file_path.is_file():
        raise HTTPException(404, f"Not found: {path}")

    # Security: no escaping repo dir
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

@app.post("/webhook")
async def webhook(request: Request):
    """GitHub push webhook — pulls latest changes."""
    body = await request.body()

    # Verify signature if secret is set
    if WEBHOOK_SECRET:
        sig = request.headers.get("X-Hub-Signature-256", "")
        expected = "sha256=" + hmac.new(
            WEBHOOK_SECRET.encode(), body, hashlib.sha256
        ).hexdigest()
        if not hmac.compare_digest(sig, expected):
            raise HTTPException(403, "Invalid signature")

    # Pull in background
    def do_pull():
        try:
            clone_or_pull()
        except Exception as e:
            print(f"Pull failed: {e}")

    threading.Thread(target=do_pull, daemon=True).start()
    return {"status": "pulling"}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=8000)
