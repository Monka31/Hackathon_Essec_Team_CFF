"""Exécution d'une analyse : clonage du repo, scanners, scan de l'URL, rapport.

Règles de sécurité de la plateforme :
- on n'exécute jamais le code analysé (pas de npm install, pas de build)
- le token GitHub n'est ni stocké ni journalisé, il ne passe que par des variables d'environnement de git
- le repo cloné est supprimé à la fin de l'analyse
- chaque action est journalisée dans data/audit.log (dont la case "je suis propriétaire")
"""
from __future__ import annotations

import base64
import json
import os
import secrets
import shutil
import subprocess
import tempfile
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..core.runner import build_report, run_repo_scanners, run_url_scanners
from ..llm.context import project_context
from ..llm.explain import enrich_report
from ..report.render import render_html, write_json
from ..scanners import LABELS, SCANNERS, URL_SCANNERS

DATA_DIR = Path(os.getenv("DATA_DIR", Path(__file__).resolve().parents[2] / "data"))
MAX_REPO_MB = int(os.getenv("MAX_REPO_MB", "500"))
CLONE_TIMEOUT_S = int(os.getenv("CLONE_TIMEOUT_S", "180"))


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def audit_log(event: str, **data: Any) -> None:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(DATA_DIR / "audit.log", "a", encoding="utf-8") as fh:
        fh.write(json.dumps({"at": _now(), "event": event, **data}, ensure_ascii=False) + "\n")


@dataclass
class Job:
    id: str
    repo_url: Optional[str]
    app_url: Optional[str]
    created_at: str
    status: str = "queued"           # queued | running | done | error
    message: str = ""
    steps: Dict[str, Dict[str, str]] = field(default_factory=dict)
    log: List[str] = field(default_factory=list)
    score: Optional[int] = None
    grade: Optional[str] = None
    counts: Dict[str, int] = field(default_factory=dict)
    has_report: bool = False
    finished_at: Optional[str] = None

    def public(self) -> Dict[str, Any]:
        return asdict(self)


class JobStore:
    def __init__(self) -> None:
        self.jobs: Dict[str, Job] = {}
        self.lock = threading.Lock()
        self.pool = ThreadPoolExecutor(max_workers=int(os.getenv("MAX_PARALLEL_JOBS", "2")))
        self.dast_pool = ThreadPoolExecutor(max_workers=2)
        self.ai_cache: Dict[str, Dict[str, Any]] = {}   # job -> {finding_id: avis IA} : survit au rapport complété par le DAST

    # --- persistance simple sur disque ---
    def _dir(self, job_id: str) -> Path:
        return DATA_DIR / "jobs" / job_id

    def save(self, job: Job) -> None:
        d = self._dir(job.id)
        d.mkdir(parents=True, exist_ok=True)
        (d / "job.json").write_text(json.dumps(job.public(), ensure_ascii=False, indent=2), encoding="utf-8")

    def get(self, job_id: str) -> Optional[Job]:
        if job_id in self.jobs:
            return self.jobs[job_id]
        p = self._dir(job_id) / "job.json"
        if p.exists() and job_id.replace("-", "").replace("_", "").isalnum():
            job = Job(**json.loads(p.read_text(encoding="utf-8")))
            self.jobs[job_id] = job
            return job
        return None

    def report_json(self, job_id: str) -> Optional[Path]:
        p = self._dir(job_id) / "report.json"
        return p if p.exists() else None

    def report_html(self, job_id: str) -> Optional[Path]:
        p = self._dir(job_id) / "report.html"
        return p if p.exists() else None

    # --- cycle de vie ---
    def create(self, repo_url: Optional[str], app_url: Optional[str], github_token: Optional[str],
               client_ip: str, consent: bool, supabase_advisor: Optional[str] = None) -> Job:
        job = Job(id=secrets.token_urlsafe(9), repo_url=repo_url, app_url=app_url, created_at=_now())
        steps = []
        if repo_url:
            steps.append("clone")
            steps += list(SCANNERS)
        if app_url:
            steps += list(URL_SCANNERS)
        if supabase_advisor:
            steps.append("supabase_paste")
        steps += ["ai", "report"]
        job.steps = {s: {"status": "pending", "message": "", "label": LABELS.get(s, s)} for s in steps}
        job.steps.get("clone", {}).update(label="Clonage du repo GitHub")
        job.steps["report"]["label"] = "Rapport"
        job.steps["ai"]["label"] = "Explications IA (4 niveaux)"
        if "supabase_paste" in job.steps:
            job.steps["supabase_paste"]["label"] = "Supabase Security Advisor (collé)"
        with self.lock:
            self.jobs[job.id] = job
        self.save(job)
        audit_log("job_created", job=job.id, ip=client_ip, repo=repo_url, url=app_url,
                  owner_consent=consent, private_repo_token=bool(github_token),
                  supabase_paste=bool(supabase_advisor))
        self.pool.submit(self._run, job, github_token, supabase_advisor)
        return job

    def _step(self, job: Job, name: str, status: str, message: str = "") -> None:
        with self.lock:
            if name in job.steps:
                job.steps[name].update(status=status, message=message[:400])
            job.log.append(f"{datetime.now().strftime('%H:%M:%S')} {LABELS.get(name, name)} : {message or status}")
        self.save(job)

    def _write_report(self, job: Job, runs, final: bool, ai: bool = False, context=None) -> None:
        report = build_report(runs, {
            "target": (job.repo_url or job.app_url or "").rstrip("/").split("/")[-1],
            "repo_url": job.repo_url, "app_url": job.app_url,
        })
        report.pop("_findings", None)
        report["job_id"] = job.id
        report["complete"] = final
        cache = self.ai_cache.setdefault(job.id, {})
        for f in report["findings"]:
            f.update(cache.get(f["id"], {}))
        if "_summary" in cache:
            report["ai_summary"] = cache["_summary"]
        if ai:
            self._step(job, "ai", "running", "analyse des failles par l'IA")
            try:
                status = enrich_report(report, context or {}, progress=lambda m: self._step(job, "ai", "running", m))
            except Exception as e:  # l'IA ne doit jamais faire échouer l'analyse : le rapport brut reste valable
                status = {"status": "error", "message": f"{type(e).__name__}: {str(e)[:200]}", "explained": 0}
                report["ai"] = status
            for f in report["findings"]:
                if f.get("explanations"):
                    cache[f["id"]] = {k: f[k] for k in ("explanations", "ai_verdict", "confidence", "confidence_reason",
                                                         "attack_scenario", "fix_steps", "prompt_injection_detected",
                                                         "injection_note") if k in f}
            if report.get("ai_summary"):
                cache["_summary"] = report["ai_summary"]
            cache["_ai_status"] = status
            self._step(job, "ai", status["status"], status["message"])
        if "_ai_status" in cache:
            report["ai"] = cache["_ai_status"]
        d = self._dir(job.id)
        write_json(report, d / "report.json")
        (d / "report.html").write_text(render_html(report), encoding="utf-8")
        with self.lock:
            job.has_report = True
            job.score, job.grade, job.counts = report["score"], report["grade"], report["counts"]
        self.save(job)

    def _run(self, job: Job, github_token: Optional[str], supabase_advisor: Optional[str] = None) -> None:
        job.status = "running"
        self.save(job)
        workdir = None
        runs = []
        context = {"url_appli": job.app_url}
        try:
            if job.repo_url:
                workdir = Path(tempfile.mkdtemp(prefix="vibeaudit-"))
                root = workdir / "repo"
                self._step(job, "clone", "running", "clonage en cours")
                clone_repo(job.repo_url, root, github_token)
                github_token = None  # on oublie le token dès qu'il ne sert plus
                size = _dir_size_mb(root)
                self._step(job, "clone", "ok", f"repo cloné ({size} Mo)")
                if size > MAX_REPO_MB:
                    raise RuntimeError(f"repo trop gros ({size} Mo, max {MAX_REPO_MB})")
                runs += run_repo_scanners(root, progress=lambda n, s, m: self._step(job, n, s, m))
                context = project_context(root, job.app_url)
                shutil.rmtree(workdir, ignore_errors=True)  # le code n'est plus utile : suppression immédiate
                self._step(job, "clone", "ok", f"repo cloné ({size} Mo), analysé puis supprimé du serveur")

            dast_pending = False
            if job.app_url:
                runs += run_url_scanners(job.app_url, skip={"snyk_dast"},
                                         progress=lambda n, s, m: self._step(job, n, s, m))
                dast_pending = "snyk_dast" in job.steps

            if supabase_advisor and "supabase_paste" in job.steps:
                self._step(job, "supabase_paste", "running", "lecture du rapport collé")
                try:
                    from ..scanners import supabase as _sb
                    from ..core.models import ScannerRun
                    sb_findings = _sb.parse_pasted(supabase_advisor)
                    r = ScannerRun(name="supabase_paste", status="ok",
                                   message=f"{len(sb_findings)} résultat(s)", findings=sb_findings)
                    runs.append(r)
                    self._step(job, "supabase_paste", "ok", f"{len(sb_findings)} problème(s) de base de données")
                except Exception as e:
                    self._step(job, "supabase_paste", "error", f"rapport illisible : {str(e)[:150]}")

            self._write_report(job, runs, final=False)             # rapport brut tout de suite
            self._step(job, "report", "running", "rapport brut prêt, explications IA en cours")
            self._write_report(job, runs, final=not dast_pending, ai=True, context=context)
            self._step(job, "report", "ok", "rapport prêt" + (" (le scan Snyk API & Web continue)" if dast_pending else ""))
            job.status, job.finished_at = "done", _now()
            self.save(job)
            audit_log("job_done", job=job.id, score=job.score)

            if dast_pending:
                self.dast_pool.submit(self._run_dast, job, runs, context)
        except Exception as e:
            msg = _redact_token(str(e), github_token)
            job.status, job.message, job.finished_at = "error", msg[:400], _now()
            for s in job.steps.values():
                if s["status"] in ("pending", "running"):
                    s["status"] = "skipped"
            job.log.append(f"Erreur : {msg[:400]}")
            self.save(job)
            audit_log("job_error", job=job.id, error=msg[:300], trace=_redact_token(traceback.format_exc()[-800:], github_token))
        finally:
            if workdir:
                shutil.rmtree(workdir, ignore_errors=True)

    def _run_dast(self, job: Job, runs, context=None) -> None:
        from ..scanners import snyk_dast
        from ..core.runner import _run_one

        run = _run_one("snyk_dast",
                       lambda: snyk_dast.scan_url(job.app_url, progress=lambda m: self._step(job, "snyk_dast", "running", m)),
                       progress=lambda n, s, m: self._step(job, n, s, m))
        self._write_report(job, runs + [run], final=True, ai=run.status == "ok" and bool(run.findings), context=context)
        msg = "rapport complet (Snyk API & Web inclus)" if run.status == "ok" else "rapport complet (sans Snyk API & Web)"
        self._step(job, "report", "ok", msg)
        audit_log("dast_done", job=job.id, status=run.status)


def _dir_size_mb(p: Path) -> float:
    total = 0
    for f in p.rglob("*"):
        try:
            if f.is_file():
                total += f.stat().st_size
        except OSError:
            pass
    return round(total / (1024 * 1024), 1)


def _redact_token(text: str, token: Optional[str]) -> str:
    return text.replace(token, "***") if token else text


def clone_repo(repo_url: str, dest: Path, token: Optional[str]) -> None:
    """Clone complet (l'historique sert à Gitleaks). Le token passe par la config git en variables d'environnement."""
    env = {
        "PATH": os.environ.get("PATH", ""),
        "HOME": str(dest.parent),
        "GIT_TERMINAL_PROMPT": "0",   # jamais de demande de mot de passe interactive
        "GIT_LFS_SKIP_SMUDGE": "1",
    }
    for k in ("HTTPS_PROXY", "HTTP_PROXY", "NO_PROXY", "https_proxy", "http_proxy", "no_proxy",
              "GIT_SSL_CAINFO", "SSL_CERT_FILE"):
        if os.environ.get(k):
            env[k] = os.environ[k]
    if token:
        basic = base64.b64encode(f"x-access-token:{token}".encode()).decode()
        env.update({
            "GIT_CONFIG_COUNT": "1",
            "GIT_CONFIG_KEY_0": "http.https://github.com/.extraheader",
            "GIT_CONFIG_VALUE_0": f"AUTHORIZATION: basic {basic}",
        })
    url = repo_url if repo_url.endswith(".git") else repo_url.rstrip("/") + ".git"
    try:
        proc = subprocess.run(
            ["git", "clone", "--quiet", "--no-tags", "--", url, str(dest)],
            env=env, capture_output=True, text=True, timeout=CLONE_TIMEOUT_S,
        )
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"clonage trop long (plus de {CLONE_TIMEOUT_S} s)")
    if proc.returncode != 0:
        err = proc.stderr.lower()
        if "not found" in err or "could not read username" in err or "authentication" in err or "403" in err:
            raise RuntimeError("repo introuvable ou privé : vérifier le lien, ou ajouter un token GitHub en lecture")
        raise RuntimeError("échec du clonage : " + _redact_token(proc.stderr.strip()[-300:], token))


STORE = JobStore()
