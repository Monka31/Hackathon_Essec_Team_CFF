"""Supabase Security Advisor : règles d'accès à la base (RLS), invisibles pour les scanners de code.

Nécessite dans le .env : SUPABASE_ACCESS_TOKEN (supabase.com/dashboard/account/tokens)
et SUPABASE_PROJECT_REF (l'identifiant du projet, visible dans l'URL du dashboard).
"""
from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from pathlib import Path
from typing import List

from ..core.models import Evidence, Finding
from .base import ScannerError, ScannerSkipped

NAME = "supabase"
API = "https://api.supabase.com/v1/projects/{ref}/advisors/security"
LEVEL_MAP = {"ERROR": "critical", "WARN": "medium", "INFO": "low"}


def scan(root: Path, timeout: int = 60) -> List[Finding]:
    token = os.getenv("SUPABASE_ACCESS_TOKEN")
    ref = os.getenv("SUPABASE_PROJECT_REF")
    if not token or not ref:
        raise ScannerSkipped("SUPABASE_ACCESS_TOKEN ou SUPABASE_PROJECT_REF absent du .env")

    req = urllib.request.Request(
        API.format(ref=ref),
        headers={"Authorization": f"Bearer {token}", "Accept": "application/json", "User-Agent": "vibeaudit"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise ScannerError("token Supabase refusé (vérifier SUPABASE_ACCESS_TOKEN)")
        if e.code == 404:
            raise ScannerError("projet Supabase introuvable (vérifier SUPABASE_PROJECT_REF)")
        raise ScannerError(f"API Supabase : HTTP {e.code}")
    except urllib.error.URLError as e:
        raise ScannerError(f"API Supabase injoignable : {e.reason}")

    findings: List[Finding] = []
    for lint in data.get("lints", []):
        meta = lint.get("metadata", {}) or {}
        obj = ".".join(x for x in (meta.get("schema"), meta.get("name")) if x)
        findings.append(
            Finding(
                category="config",
                title=lint.get("title") or lint.get("name", "Problème de configuration Supabase"),
                severity=LEVEL_MAP.get(str(lint.get("level", "")).upper(), "medium"),
                file=f"supabase:{obj}" if obj else "supabase",
                line=None,
                snippet=None,
                description=(lint.get("detail") or lint.get("description") or "").strip(),
                fix_hint=lint.get("remediation"),
                references=[lint["remediation"]] if str(lint.get("remediation", "")).startswith("http") else [],
                evidence=[Evidence(source=NAME, rule_id=lint.get("name", ""), raw=lint)],
            )
        )
    return findings
