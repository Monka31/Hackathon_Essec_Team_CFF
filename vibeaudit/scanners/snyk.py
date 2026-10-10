"""Snyk : code (Snyk Code, SAST) et dépendances (Snyk Open Source, SCA), via la CLI.

Authentification : 'snyk auth' une fois sur la machine, ou SNYK_TOKEN dans le .env.
Attention au quota de tests de l'offre gratuite : on peut désactiver Snyk avec --skip snyk_code,snyk_deps.
"""
from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Dict, List

from ..core.models import Evidence, Finding
from .base import ScannerError, ScannerSkipped, find_line, read_snippet, require_binary, run_cmd, to_rel

LEVEL_MAP = {"error": "high", "warning": "medium", "note": "low", "none": "low"}
SEV_MAP = {"critical": "critical", "high": "high", "medium": "medium", "low": "low"}


def _run_snyk(args: List[str], root: Path, timeout: int) -> dict:
    require_binary("snyk", "npm install -g snyk, puis snyk auth")
    # Codes Snyk : 0 = rien trouvé, 1 = failles trouvées, 2 = échec, 3 = projet non supporté
    try:
        proc = run_cmd(
            ["snyk"] + args + ["--json"], cwd=root, timeout=timeout, ok_codes=(0, 1, 2, 3),
            env_extra={"SNYK_TOKEN": os.getenv("SNYK_TOKEN", "")},
        )
    except ScannerError:
        raise
    if proc.returncode == 3:
        raise ScannerSkipped("aucun projet supporté par Snyk dans ce dossier")
    if not (proc.stdout or "").strip():
        # Snyk peut sortir en code 0 sans rien produire (réseau coupé, binaire non téléchargé...)
        tail = " | ".join((proc.stderr or "").strip().splitlines()[-2:])
        raise ScannerError("aucune sortie de Snyk (réseau ?) " + tail[:250])
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise ScannerError((proc.stderr or proc.stdout or "sortie illisible").strip()[:300])
    if proc.returncode == 2 or (isinstance(data, dict) and data.get("ok") is False and data.get("error")):
        msg = data.get("error") if isinstance(data, dict) else None
        msg = msg or (proc.stderr or "").strip()
        if "auth" in str(msg).lower():
            raise ScannerSkipped("Snyk n'est pas authentifié (lancer 'snyk auth')")
        raise ScannerError(str(msg)[:300])
    return data


def scan_code(root: Path, timeout: int = 900) -> List[Finding]:
    """Snyk Code renvoie du SARIF."""
    data = _run_snyk(["code", "test"], root, timeout)
    findings: List[Finding] = []
    for run in data.get("runs", []):
        rules: Dict[str, dict] = {r.get("id"): r for r in run.get("tool", {}).get("driver", {}).get("rules", [])}
        for res in run.get("results", []):
            rule_id = res.get("ruleId", "snyk")
            rule = rules.get(rule_id, {})
            loc = (res.get("locations") or [{}])[0].get("physicalLocation", {})
            rel = to_rel(root, loc.get("artifactLocation", {}).get("uri", ""))
            line = loc.get("region", {}).get("startLine")
            props = rule.get("properties", {}) or {}
            title = (rule.get("shortDescription", {}) or {}).get("text") or rule.get("name") or rule_id
            findings.append(
                Finding(
                    category="code",
                    title=title,
                    severity=LEVEL_MAP.get(res.get("level", "warning"), "medium"),
                    file=rel,
                    line=line,
                    snippet=read_snippet(root, rel, line),
                    description=(res.get("message", {}) or {}).get("text", ""),
                    cwe=[str(c) for c in props.get("cwe", [])],
                    references=[],
                    evidence=[Evidence(source="snyk_code", rule_id=rule_id, raw=res)],
                )
            )
    return findings


def scan_deps(root: Path, timeout: int = 600) -> List[Finding]:
    data = _run_snyk(["test"], root, timeout)
    projects = data if isinstance(data, list) else [data]
    by_pkg: Dict[str, Finding] = {}
    for proj in projects:
        target = proj.get("displayTargetFile") or "package.json"
        for v in proj.get("vulnerabilities", []):
            pkg = v.get("packageName") or v.get("moduleName") or "?"
            ids = v.get("identifiers", {}) or {}
            cwe = ids.get("CWE", []) or []
            refs = [f"https://security.snyk.io/vuln/{v.get('id')}"] if v.get("id") else []
            sev = SEV_MAP.get(v.get("severity", "low"), "low")
            upgrade = [u for u in (v.get("upgradePath") or []) if u]
            hint = f"Mettre à jour vers {upgrade[0]}" if upgrade and v.get("isUpgradable") else None
            f = by_pkg.get(pkg)
            if f is None:
                direct = len(v.get("from", [])) <= 2
                line = find_line(root, target, f'"{pkg}"') if direct else None
                f = Finding(
                    category="dependency",
                    title=f"Dépendance vulnérable : {pkg}",
                    severity=sev,
                    file=target,
                    line=line,
                    snippet=read_snippet(root, target, line, context=0) if line else None,
                    description="",
                    package=pkg,
                    fix_hint=hint,
                    evidence=[],
                )
                by_pkg[pkg] = f
            f.description = (f.description + f"\n- {v.get('title')} ({', '.join(ids.get('CVE', []) or [v.get('id', '')])})").strip()
            f.cwe = sorted(set(f.cwe) | set(cwe))
            f.references = list(dict.fromkeys(f.references + refs))[:5]
            if ["critical", "high", "medium", "low"].index(sev) < ["critical", "high", "medium", "low"].index(f.severity):
                f.severity = sev
            f.fix_hint = f.fix_hint or hint
            f.evidence.append(Evidence(source="snyk_deps", rule_id=v.get("id", ""), raw={
                k: v.get(k) for k in ("id", "title", "severity", "packageName", "version", "from", "identifiers", "upgradePath", "isUpgradable", "cvssScore")
            }))
    return list(by_pkg.values())
