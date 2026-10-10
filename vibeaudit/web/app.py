"""Plateforme web : formulaire, suivi en direct, rapport.

Lancer : python -m vibeaudit serve            (puis http://127.0.0.1:8000)
Sur le serveur : python -m vibeaudit serve --host 0.0.0.0 --port 8000
"""
from __future__ import annotations

import hmac
import os
from pathlib import Path

from fastapi import FastAPI, Form, HTTPException, Request
from fastapi.responses import FileResponse, HTMLResponse, JSONResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

from .. import __version__
from ..config import load_env
from ..core.net import UnsafeURL, check_public_url, parse_github_url

load_env()
from .jobs import STORE, audit_log  # noqa: E402  (après load_env pour lire DATA_DIR)

HERE = Path(__file__).resolve().parent
templates = Jinja2Templates(directory=str(HERE / "templates"))
app = FastAPI(title="vibeaudit", version=__version__, docs_url=None, redoc_url=None)


def _access_code() -> str:
    return os.getenv("PLATFORM_ACCESS_CODE", "")


def _client_ip(request: Request) -> str:
    fwd = request.headers.get("x-forwarded-for", "")
    return fwd.split(",")[0].strip() if fwd else (request.client.host if request.client else "?")


@app.middleware("http")
async def security_headers(request: Request, call_next):
    # On applique à notre plateforme ce qu'on reproche aux autres
    resp = await call_next(request)
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
        "img-src 'self' data:; frame-ancestors 'none'"
    )
    return resp


@app.get("/", response_class=HTMLResponse)
def index(request: Request):
    return templates.TemplateResponse(request, "index.html", {"need_code": bool(_access_code()), "error": None, "form": {}})


@app.post("/scan")
def start_scan(
    request: Request,
    repo_url: str = Form(""),
    app_url: str = Form(""),
    github_token: str = Form(""),
    owner_consent: str = Form(""),
    access_code: str = Form(""),
):
    repo_url, app_url, github_token = repo_url.strip(), app_url.strip(), github_token.strip()
    form = {"repo_url": repo_url, "app_url": app_url}

    def fail(msg: str):
        return templates.TemplateResponse(request, "index.html", {"need_code": bool(_access_code()), "error": msg, "form": form},
                                          status_code=400)

    if _access_code() and not hmac.compare_digest(access_code.strip(), _access_code()):
        return fail("Code d'accès incorrect.")
    if not repo_url and not app_url:
        return fail("Indique au moins un lien GitHub ou une URL d'appli.")
    if repo_url and not parse_github_url(repo_url):
        return fail("Lien GitHub invalide. Format attendu : https://github.com/compte/projet")
    if app_url:
        try:
            check_public_url(app_url)
        except UnsafeURL as e:
            return fail(f"URL refusée : {e}")
    if owner_consent != "yes":
        return fail("Tu dois certifier être propriétaire du projet ou autorisé à le tester.")
    if github_token and not (github_token.startswith(("github_pat_", "ghp_", "gho_", "ghs_")) and len(github_token) < 300):
        return fail("Token GitHub au format inattendu.")

    job = STORE.create(repo_url or None, app_url or None, github_token or None, _client_ip(request), consent=True)
    return RedirectResponse(f"/jobs/{job.id}", status_code=303)


@app.get("/jobs/{job_id}", response_class=HTMLResponse)
def job_page(request: Request, job_id: str):
    job = STORE.get(job_id)
    if not job:
        raise HTTPException(404, "Analyse introuvable")
    return templates.TemplateResponse(request, "job.html", {"job": job})


@app.get("/api/jobs/{job_id}")
def job_status(job_id: str):
    job = STORE.get(job_id)
    if not job:
        raise HTTPException(404, "Analyse introuvable")
    return JSONResponse(job.public())


@app.get("/jobs/{job_id}/report", response_class=HTMLResponse)
def job_report(job_id: str):
    p = STORE.report_html(job_id)
    if not p:
        raise HTTPException(404, "Rapport pas encore prêt")
    return FileResponse(p, media_type="text/html")


@app.get("/api/jobs/{job_id}/report")
def job_report_json(job_id: str):
    p = STORE.report_json(job_id)
    if not p:
        raise HTTPException(404, "Rapport pas encore prêt")
    return FileResponse(p, media_type="application/json")


@app.get("/api/health")
def health():
    return {"ok": True, "version": __version__}
