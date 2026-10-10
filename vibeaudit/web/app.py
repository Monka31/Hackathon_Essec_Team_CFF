"""Plateforme web : sert le prototype (interface) et l'API qu'il attend.

Lancer : python -m vibeaudit serve            (puis http://127.0.0.1:8000)
"""
from __future__ import annotations

import json
import os
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse

from .. import __version__
from ..config import load_env
from ..core.net import UnsafeURL, check_public_url, parse_github_url

load_env()
from . import adapter  # noqa: E402
from .jobs import STORE, audit_log  # noqa: E402

HERE = Path(__file__).resolve().parent
app = FastAPI(title="vibeaudit", version=__version__, docs_url=None, redoc_url=None)


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(HERE / "prototype.html", media_type="text/html")


@app.post("/api/audits")
async def start_audit(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    repo_url = (body.get("repo_url") or "").strip()
    app_url = (body.get("url") or "").strip()
    consent = bool(body.get("owner_consent"))

    if not repo_url and not app_url:
        raise HTTPException(400, "Provide an app URL, a GitHub repo, or both.")
    if repo_url and not parse_github_url(repo_url):
        raise HTTPException(400, "Invalid GitHub URL. Expected https://github.com/owner/project")
    if app_url:
        try:
            check_public_url(app_url)
        except UnsafeURL as e:
            raise HTTPException(400, f"URL refused: {e}")
    if not consent:
        raise HTTPException(400, "You must confirm you own this project or are authorized to test it.")

    job = STORE.create(repo_url or None, app_url or None, None, _client_ip(request), consent=True)
    return {"audit_id": job.id}


@app.get("/api/audits/{job_id}/status")
def audit_status(job_id: str):
    job = STORE.get(job_id)
    if not job:
        raise HTTPException(404, "Audit not found")
    return JSONResponse(adapter.status_payload(job.public()))


@app.get("/api/audits/{job_id}/report")
def audit_report(job_id: str):
    p = STORE.report_json(job_id)
    if not p:
        raise HTTPException(404, "Report not ready")
    report = json.loads(p.read_text(encoding="utf-8"))
    return JSONResponse(adapter.to_prototype(report))


# --- Stubs pour que les écrans du prototype ne cassent pas (pas encore branchés) ---
@app.post("/api/auth/signup")
async def signup(request: Request):
    try:
        body = await request.json()
    except Exception:
        body = {}
    email = body.get("email")
    name = (email.split("@")[0] if email else "Founder")
    return {"user": {"id": "u_demo", "name": name, "email": email}}


@app.get("/api/projects")
def projects():
    return []


@app.post("/api/audits/{job_id}/findings/{fid}/fix")
def create_fix(job_id: str, fid: str):
    # La correction automatique par PR n'est pas encore branchée : on renvoie la proposition sans l'appliquer.
    p = STORE.report_json(job_id)
    steps = []
    if p:
        rep = json.loads(p.read_text(encoding="utf-8"))
        f = next((x for x in rep.get("findings", []) if x["id"] == fid), None)
        if f:
            steps = f.get("fix_steps") or []
    return {
        "fix_id": f"fx_{job_id}_{fid}", "finding_id": fid, "status": "pr_created",
        "plain_change": "Suggested fix (preview). Automatic pull requests are coming soon.",
        "reassurance": "Nothing is changed in your repository yet.",
        "file": "", "diff": [f"+ {s}" for s in steps] or ["+ (see the fix steps in the report)"],
        "checks": [], "pr_url": None,
    }


@app.get("/api/fixes/{fix_id}")
def get_fix(fix_id: str):
    return {"fix_id": fix_id, "status": "pr_created", "diff": [], "checks": [], "pr_url": None,
            "plain_change": "Preview only.", "reassurance": "", "file": ""}


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}
