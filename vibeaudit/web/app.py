"""Plateforme web Syberia : sert le visuel (prototype.html) et l'API qu'il attend.

Lancer : python -m vibeaudit serve            (puis http://127.0.0.1:8000)
Sécurité : jetons GitHub jamais stockés, cookies de session httpOnly, le code audité
n'est jamais exécuté, aucune attaque active.
"""
from __future__ import annotations

import io
import json
import os
import re
import secrets
import tempfile
import zipfile
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse

from .. import __version__
from ..config import load_env
from ..core.net import UnsafeURL, check_public_url, parse_github_url

load_env()
from . import adapter, db, fixes, github_app  # noqa: E402
from .jobs import STORE, audit_log  # noqa: E402

HERE = Path(__file__).resolve().parent
app = FastAPI(title="vibeaudit", version=__version__, docs_url=None, redoc_url=None)
db.init()

MAX_ZIP_MB = int(os.getenv("MAX_ZIP_MB", "50"))
COOKIE = "sid"
_oauth_states: Dict[str, bool] = {}

# Les identifiants d'audit sont générés par le serveur (type UUID). On les valide
# strictement à la frontière de l'API pour empêcher toute tentative de path traversal
# si une couche sous-jacente venait à construire un chemin disque à partir de cette valeur.
_SAFE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,64}$")


def _validate_safe_id(value: str) -> str:
    if not value or not _SAFE_ID_RE.fullmatch(value):
        raise HTTPException(400, "Invalid identifier.")
    return value


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")


def _current_user(request: Request) -> Optional[Dict[str, Any]]:
    return db.user_by_session(request.cookies.get(COOKIE))


def _set_session(resp, user: Dict[str, Any]) -> None:
    token = db.create_session(user["db_id"])
    resp.set_cookie(COOKIE, token, max_age=db.SESSION_DAYS * 86400, httponly=True, samesite="lax", path="/")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["Referrer-Policy"] = "no-referrer"
    return resp


@app.get("/", response_class=HTMLResponse)
def index():
    return FileResponse(HERE / "prototype.html", media_type="text/html",
                        headers={"Cache-Control": "no-store, no-cache, must-revalidate, max-age=0"})


# ============================================================ AUDITS
def _unzip_to_temp(data: bytes) -> str:
    if len(data) > MAX_ZIP_MB * 1024 * 1024:
        raise HTTPException(400, f"ZIP too large (max {MAX_ZIP_MB} MB).")
    dest = Path(tempfile.mkdtemp(prefix="vibeaudit-zip-"))
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as z:
            for name in z.namelist():
                p = (dest / name).resolve()
                if not str(p).startswith(str(dest.resolve())):
                    raise HTTPException(400, "Unsafe path in ZIP.")
            z.extractall(dest)
    except zipfile.BadZipFile:
        raise HTTPException(400, "This file is not a valid ZIP.")
    # si tout est dans un seul dossier racine, on descend dedans
    entries = [e for e in dest.iterdir() if e.name not in ("__MACOSX",)]
    if len(entries) == 1 and entries[0].is_dir():
        return str(entries[0])
    return str(dest)


@app.post("/api/audits")
async def start_audit(request: Request):
    user = _current_user(request)
    user_db_id = user["db_id"] if user else None
    ctype = request.headers.get("content-type", "")

    repo_url = app_url = supabase_advisor = None
    local_root = None
    github_token = None
    active = False

    if ctype.startswith("multipart/form-data"):
        form = await request.form()
        up = form.get("file")
        if up is None:
            raise HTTPException(400, "No file provided.")
        local_root = _unzip_to_temp(await up.read())
    else:
        try:
            body = await request.json()
        except Exception:
            body = {}
        atype = (body.get("type") or "quick").strip()
        app_url = (body.get("url") or "").strip() or None
        repo_url = (body.get("repo_url") or "").strip() or None
        supabase_advisor = ((body.get("supabase_advisor") or "").strip() or None)
        if supabase_advisor:
            supabase_advisor = supabase_advisor[:20000]
        active = bool(body.get("active_consent"))
        provider = (body.get("provider") or "").strip()
        # audit profond via GitHub : il faut un repo (owner/name ou URL)
        if atype == "deep" and provider == "github" and not repo_url:
            raise HTTPException(400, "Add your GitHub repository (owner/name) to run a deep audit, or upload a ZIP.")

    if app_url:
        try:
            check_public_url(app_url)
        except UnsafeURL as e:
            raise HTTPException(400, f"URL refused: {e}")
    if repo_url:
        gh = parse_github_url(repo_url) or (repo_url.count("/") == 1 and repo_url)
        if not gh:
            raise HTTPException(400, "Invalid GitHub repository. Use owner/name or a github.com URL.")
        if repo_url.count("/") == 1 and not repo_url.startswith("http"):
            repo_url = "https://github.com/" + repo_url
        # jeton d'installation court pour cloner (y compris privé), jamais stocké
        if github_app.is_configured():
            parts = [x for x in repo_url.split("/") if x]
            if len(parts) >= 2:
                github_token = github_app.token_for_repo(parts[-2], parts[-1].replace(".git", ""))

    if not (repo_url or app_url or local_root):
        raise HTTPException(400, "Provide an app URL, a GitHub repo, or a ZIP.")

    job = STORE.create(repo_url, app_url, github_token, _client_ip(request), consent=True,
                       supabase_advisor=supabase_advisor, user_db_id=user_db_id, local_root=local_root,
                       active=bool(active and app_url))
    return {"audit_id": job.id}


@app.get("/api/audits/{job_id}/status")
def audit_status(job_id: str):
    job_id = _validate_safe_id(job_id)
    job = STORE.get(job_id)
    if not job:
        raise HTTPException(404, "Audit not found")
    return JSONResponse(adapter.status_payload(job.public()))


@app.get("/api/audits/{job_id}/report")
def audit_report
