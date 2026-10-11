"""Snyk API & Web (ex-Probely) : scan dynamique (DAST) de l'appli en ligne.

Prérequis :
- PROBELY_API_KEY dans le .env (Snyk API & Web > Settings > Integrations > API keys)
- le domaine doit être VÉRIFIÉ dans Snyk API & Web (balise, fichier ou DNS) : sans ça, pas de scan.
Le scan prend plusieurs minutes : la plateforme le lance en arrière-plan et complète le rapport ensuite.
"""
from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Callable, List, Optional

from ..core.models import Evidence, Finding
from .base import ScannerError, ScannerSkipped

NAME = "snyk_dast"
DONE = {"completed", "completed_with_errors", "failed", "canceled"}


def _base() -> str:
    return os.getenv("PROBELY_API_URL", "https://api.probely.com").rstrip("/")


def _api(method: str, path: str, body: Optional[dict] = None, timeout: int = 30) -> dict:
    key = os.getenv("PROBELY_API_KEY")
    if not key:
        raise ScannerSkipped("PROBELY_API_KEY absent du .env")
    data = json.dumps(body).encode() if body is not None else None
    req = urllib.request.Request(
        _base() + path, data=data, method=method,
        headers={"Authorization": f"JWT {key}", "Content-Type": "application/json", "Accept": "application/json"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            txt = r.read().decode()
            return json.loads(txt) if txt else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode(errors="replace")[:300]
        if e.code in (401, 403):
            raise ScannerError(f"clé Snyk API & Web refusée ou droits insuffisants ({e.code}) {detail}")
        raise ScannerError(f"Snyk API & Web : HTTP {e.code} sur {path} {detail}")
    except urllib.error.URLError as e:
        raise ScannerError(f"Snyk API & Web injoignable : {e.reason}")


def _host(url: str) -> str:
    return (urllib.parse.urlparse(url).hostname or "").lower()


def find_or_create_target(url: str) -> dict:
    host = _host(url)
    page = 1
    while page <= 10:
        data = _api("GET", f"/targets/?page={page}")
        for t in data.get("results", []):
            if _host((t.get("site") or {}).get("url", "")) == host:
                return t
        if page >= int(data.get("page_total") or 1):
            break
        page += 1
    return _api("POST", "/targets/", {"site": {"name": f"vibeaudit {host}", "url": url}})


def _severity(n) -> str:
    try:
        n = int(n)
    except (TypeError, ValueError):
        return "medium"
    if n >= 40:
        return "critical"
    if n >= 30:
        return "high"
    if n >= 20:
        return "medium"
    return "low"


def scan_url(url: str, progress: Optional[Callable[[str], None]] = None, max_wait_s: Optional[int] = None) -> List[Finding]:
    max_wait_s = max_wait_s or int(os.getenv("DAST_MAX_WAIT_S", "1800"))
    say = progress or (lambda m: None)

    target = find_or_create_target(url)
    tid = target.get("id")
    site = target.get("site") or {}
    if not site.get("verified"):
        raise ScannerSkipped(
            "domaine non vérifié dans Snyk API & Web : dans plus.probely.app, ouvrir la cible et suivre "
            "'Verify domain' avant de relancer. Le jeton de vérification reste dans votre compte Snyk."
        )

    body = {"scan_profile": os.getenv("PROBELY_SCAN_PROFILE")} if os.getenv("PROBELY_SCAN_PROFILE") else None
    scan = _api("POST", f"/targets/{tid}/scan_now/", body)
    sid = scan.get("id")
    say(f"scan Snyk lancé ({sid}), en attente...")

    t0, status = time.time(), scan.get("status", "queued")
    while status not in DONE:
        if time.time() - t0 > max_wait_s:
            raise ScannerError(f"scan toujours en cours après {max_wait_s // 60} min (statut : {status}), voir plus.probely.app")
        time.sleep(20)
        status = _api("GET", f"/targets/{tid}/scans/{sid}/").get("status", status)
        say(f"scan Snyk : {status} ({int(time.time() - t0)} s)")
    if status in ("failed", "canceled"):
        raise ScannerError(f"scan Snyk terminé avec le statut '{status}'")

    findings: List[Finding] = []
    page = 1
    while page <= 20:
        data = _api("GET", f"/targets/{tid}/findings/?scan={sid}&page={page}")
        for f in data.get("results", []):
            d = f.get("definition") or {}
            where = f"{(f.get('method') or 'GET').upper()} {f.get('url', url)}"
            if f.get("parameter"):
                where += f" (paramètre '{f['parameter']}')"
            ev = f.get("evidence")
            findings.append(
                Finding(
                    category="web",
                    title=d.get("name") or "Faille détectée par Snyk API & Web",
                    severity=_severity(f.get("severity")),
                    file=f.get("url") or url,
                    line=None,
                    snippet=(str(ev)[:1500] if ev else None),
                    description=f"{where}\n{(d.get('desc') or '').strip()[:1500]}",
                    fix_hint=(f.get("fix") or "").strip()[:1500] or None,
                    evidence=[Evidence(source=NAME, rule_id=str(d.get("id") or d.get("name") or ""), raw={
                        k: f.get(k) for k in ("id", "severity", "url", "method", "parameter", "state", "cvss_score")
                    })],
                )
            )
        if page >= int(data.get("page_total") or 1):
            break
        page += 1
    return findings
