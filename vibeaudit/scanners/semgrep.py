"""Semgrep : analyse statique du code (SAST), gratuit et sans quota."""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import List

from ..core.models import Evidence, Finding, FindingList
from .base import EXCLUDED_DIRS, ScannerError, read_snippet, require_binary, run_cmd, to_rel

NAME = "semgrep"

# Jeux de règles du registre Semgrep (nécessite l'accès à semgrep.dev).
# Si le réseau bloque, mettre SEMGREP_RULES_DIR=/chemin/vers/regles dans le .env.
DEFAULT_CONFIGS = ["p/default", "p/owasp-top-ten", "p/javascript", "p/typescript", "p/react",
                   "p/nextjs", "p/nodejsscan", "p/python", "p/jwt", "p/insecure-transport", "p/secrets"]

SEVERITY_MAP = {"ERROR": "high", "WARNING": "medium", "INFO": "low"}


def _severity(res: dict) -> str:
    extra = res.get("extra", {})
    meta = extra.get("metadata", {}) or {}
    sev = SEVERITY_MAP.get(str(extra.get("severity", "")).upper(), "low")
    # Impact et probabilité élevés : on remonte en critique
    if sev == "high" and str(meta.get("impact", "")).upper() == "HIGH" and str(
        meta.get("likelihood", "")
    ).upper() == "HIGH":
        sev = "critical"
    return sev


def _category(check_id: str) -> str:
    cid = check_id.lower()
    if "secret" in cid or "hardcoded" in cid or "credential" in cid or "api-key" in cid:
        return "secret"
    return "code"


def configs() -> List[str]:
    """Jeux de règles utilisés, partagés avec la vérification des correctifs (web/fix_checks.py)."""
    rules_dir = os.getenv("SEMGREP_RULES_DIR")
    if rules_dir:
        return [rules_dir]
    return [c.strip() for c in os.getenv("SEMGREP_CONFIGS", ",".join(DEFAULT_CONFIGS)).split(",") if c.strip()]


def scan(root: Path, timeout: int = 900) -> List[Finding]:
    require_binary("semgrep", "brew install semgrep")
    rule_sets = configs()

    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--timeout", "30"]
    for c in rule_sets:
        cmd += ["--config", c]
    for d in sorted(EXCLUDED_DIRS):  # ne pas perdre de temps sur le code généré (filtré ensuite de toute façon)
        cmd += ["--exclude", d]
    cmd.append(".")
    # 0 = rien trouvé, 1 = failles trouvées
    proc = run_cmd(cmd, cwd=root, timeout=timeout, ok_codes=(0, 1))
    if not (proc.stdout or "").strip():
        # Semgrep a planté sans rien produire : ne surtout pas afficher "0 faille"
        tail = " | ".join((proc.stderr or "").strip().splitlines()[-2:])
        raise ScannerError("Semgrep n'a rien renvoyé : " + tail[:250])
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise ScannerError("sortie JSON de Semgrep illisible")
    fatal = [e for e in data.get("errors", []) if str(e.get("level", "")).lower() == "error"
             and "rule" in str(e.get("type", "")).lower()]
    if fatal and not data.get("results"):
        raise ScannerError("règles Semgrep inutilisables : " + str(fatal[0].get("message", ""))[:250])

    scanned = len((data.get("paths") or {}).get("scanned") or [])
    findings: List[Finding] = FindingList(note=f"{scanned} fichier(s) analysé(s), règles : {', '.join(rule_sets)[:120]}")
    if scanned == 0:
        raise ScannerError("Semgrep n'a analysé aucun fichier (langage non supporté ou règles introuvables)")
    for res in data.get("results", []):
        extra = res.get("extra", {})
        meta = extra.get("metadata", {}) or {}
        check_id = res.get("check_id", "semgrep")
        rel = to_rel(root, res.get("path", ""))
        line = (res.get("start") or {}).get("line")
        cwe = meta.get("cwe") or []
        if isinstance(cwe, str):
            cwe = [cwe]
        refs = meta.get("references") or []
        if isinstance(refs, str):
            refs = [refs]
        short_rule = check_id.split(".")[-1].replace("-", " ")
        findings.append(
            Finding(
                category=_category(check_id),
                title=short_rule[:1].upper() + short_rule[1:],
                severity=_severity(res),
                file=rel,
                line=line,
                snippet=read_snippet(root, rel, line),
                description=extra.get("message", ""),
                cwe=[str(c).split(":")[0].strip() for c in cwe],
                fix_hint=extra.get("fix"),
                references=[str(r) for r in refs][:5],
                evidence=[Evidence(source=NAME, rule_id=check_id, raw=res)],
            )
        )
    return findings
