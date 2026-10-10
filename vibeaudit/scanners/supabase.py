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
LEVEL_MAP = {"ERROR": "critical", "WARN": "medium", "WARNING": "medium", "INFO": "low"}


def _title_en(lint: dict) -> str:
    name = str(lint.get("name", "")).lower()
    if "rls" in name and ("disabled" in name or "no_rls" in name or name == "rls_disabled_in_public"):
        return "Table without Row Level Security (readable by anyone with the public key)"
    return lint.get("title") or lint.get("name") or "Supabase configuration issue"


def lints_to_findings(lints: list, source: str = NAME) -> List[Finding]:
    findings: List[Finding] = []
    for lint in lints or []:
        if not isinstance(lint, dict):
            continue
        meta = lint.get("metadata", {}) or {}
        obj = ".".join(x for x in (meta.get("schema"), meta.get("name")) if x)
        findings.append(
            Finding(
                category="config",
                title=_title_en(lint),
                severity=LEVEL_MAP.get(str(lint.get("level", "")).upper(), "medium"),
                file=f"supabase:{obj}" if obj else "supabase (database)",
                line=None,
                snippet=None,
                description=(lint.get("detail") or lint.get("description") or "").strip(),
                fix_hint=lint.get("remediation") or "Enable Row Level Security and add a policy, or review the flagged object in Supabase.",
                references=[lint["remediation"]] if str(lint.get("remediation", "")).startswith("http") else [],
                evidence=[Evidence(source=source, rule_id=lint.get("name", ""), raw=lint)],
            )
        )
    return findings


# Mots-clés pour le collage en texte libre (quand l'utilisateur copie la page, pas le JSON)
_TEXT_RULES = [
    (("rls disabled", "row level security disabled", "rls not enabled", "no rls", "policy exists rls disabled"),
     "critical", "Table without Row Level Security"),
    (("security definer view", "exposed auth users", "exposed", "anonymous access"),
     "high", "Object exposed / over-permissive access"),
    (("function search_path", "mutable search_path", "extension in public"),
     "medium", "Risky database configuration"),
]


def parse_pasted(text: str, source: str = "supabase_paste") -> List[Finding]:
    """Transforme un rapport Security Advisor collé (JSON de l'API, ou texte copié) en findings."""
    text = (text or "").strip()
    if not text:
        return []
    # 1) JSON (réponse de l'API, ou export "Copy as JSON")
    try:
        data = json.loads(text)
        lints = data.get("lints") if isinstance(data, dict) else data
        if isinstance(lints, list):
            return lints_to_findings(lints, source=source)
    except json.JSONDecodeError:
        pass
    # 2) Texte libre : une ligne = une entrée, gravité devinée par mots-clés
    findings: List[Finding] = []
    for raw in text.splitlines():
        line = raw.strip()
        if len(line) < 4:
            continue
        low = line.lower()
        matched = None
        for keys, sev, title in _TEXT_RULES:
            if any(k in low for k in keys):
                matched = (sev, title)
                break
        if not matched:
            continue
        sev, title = matched
        findings.append(
            Finding(category="config", title=title, severity=sev,
                    file="supabase (database)", line=None, snippet=None,
                    description=line[:400],
                    fix_hint="Enable Row Level Security and add a policy for this table, or fix the flagged object in Supabase.",
                    evidence=[Evidence(source=source, rule_id="pasted", raw={"line": line[:400]})])
        )
    return findings



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

    return lints_to_findings(data.get("lints", []))
