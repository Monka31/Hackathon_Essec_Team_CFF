"""npm audit : dépendances JavaScript vulnérables (gratuit, livré avec Node)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..core.models import Evidence, Finding
from .base import ScannerError, ScannerSkipped, find_line, read_snippet, require_binary, run_cmd

NAME = "npm_audit"
SEVERITY_MAP = {"critical": "critical", "high": "high", "moderate": "medium", "low": "low", "info": "low"}


def scan(root: Path, timeout: int = 300) -> List[Finding]:
    if not (root / "package.json").exists():
        raise ScannerSkipped("pas de package.json (projet non JavaScript)")
    if not (root / "package-lock.json").exists():
        raise ScannerSkipped("pas de package-lock.json (lancer 'npm install' dans le projet)")
    require_binary("npm", "installer Node.js")

    # npm audit renvoie 1 quand il trouve des failles
    proc = run_cmd(["npm", "audit", "--json"], cwd=root, timeout=timeout, ok_codes=(0, 1))
    try:
        data = json.loads(proc.stdout or "{}")
    except json.JSONDecodeError:
        raise ScannerError("sortie JSON illisible")
    if "error" in data:
        raise ScannerError(str(data["error"].get("summary", data["error"]))[:300])

    findings: List[Finding] = []
    for name, vuln in (data.get("vulnerabilities") or {}).items():
        advisories = [v for v in vuln.get("via", []) if isinstance(v, dict)]
        via_pkgs = [v for v in vuln.get("via", []) if isinstance(v, str)]
        titles = [a.get("title", "") for a in advisories]
        cwe = sorted({c for a in advisories for c in (a.get("cwe") or [])})
        refs = [a.get("url") for a in advisories if a.get("url")]

        if titles:
            title = f"Dépendance vulnérable : {name} ({len(titles)} faille(s) connue(s))"
            desc = "\n".join(f"- {t}" for t in titles)
        else:
            title = f"Dépendance vulnérable : {name} (via {', '.join(via_pkgs)})"
            desc = f"Hérite des failles de : {', '.join(via_pkgs)}"

        direct = bool(vuln.get("isDirect"))
        file = "package.json" if direct else "package-lock.json"
        line = find_line(root, file, f'"{name}"') if direct else find_line(root, file, f'node_modules/{name}"')

        fix = vuln.get("fixAvailable")
        if isinstance(fix, dict):
            hint = f"Mettre à jour vers {fix.get('name')}@{fix.get('version')}"
            if fix.get("isSemVerMajor"):
                hint += " (version majeure : tester l'appli après la mise à jour)"
        elif fix is True:
            hint = "Correctif disponible : 'npm audit fix'"
        else:
            hint = "Pas de correctif automatique : remplacer la dépendance ou surveiller"

        findings.append(
            Finding(
                category="dependency",
                title=title,
                severity=SEVERITY_MAP.get(vuln.get("severity", "low"), "low"),
                file=file,
                line=line,
                snippet=read_snippet(root, file, line, context=0) if direct else None,
                description=desc + f"\nVersions concernées : {vuln.get('range', '?')}"
                + ("" if direct else " (dépendance indirecte)"),
                cwe=cwe,
                package=name,
                fix_hint=hint,
                references=refs[:5],
                evidence=[Evidence(source=NAME, rule_id=",".join(r.split("/")[-1] for r in refs) or name, raw=vuln)],
            )
        )
    return findings
