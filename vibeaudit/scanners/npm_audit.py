"""npm audit : dépendances JavaScript vulnérables (gratuit, livré avec Node)."""
from __future__ import annotations

import json
import os
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
    if not (proc.stdout or "").strip():
        raise ScannerError("npm audit n'a rien renvoyé (registre npm injoignable ?)")
    try:
        data = json.loads(proc.stdout)
    except json.JSONDecodeError:
        raise ScannerError("sortie JSON illisible")
    if "error" in data:
        raise ScannerError(str(data["error"].get("summary", data["error"]))[:300])

    vulns = data.get("vulnerabilities") or {}
    # NPM_AUDIT_MODE=direct : une ligne par dépendance directe (celle que le dev doit mettre à jour),
    # avec les failles des sous-dépendances regroupées dedans. "all" (défaut) : une ligne par paquet.
    direct_mode = os.getenv("NPM_AUDIT_MODE", "direct") != "all"

    def collect(name, seen):
        # Toutes les failles (avis) d'un paquet et de ses sous-dépendances vulnérables
        if name in seen or name not in vulns:
            return []
        seen.add(name)
        out = []
        for v in vulns[name].get("via", []):
            out += [v] if isinstance(v, dict) else collect(v, seen)
        return out

    findings: List[Finding] = []
    for name, vuln in vulns.items():
        if direct_mode and not vuln.get("isDirect"):
            continue
        if direct_mode:
            advisories = list({a.get("url") or a.get("title"): a for a in collect(name, set())}.values())
        else:
            advisories = [v for v in vuln.get("via", []) if isinstance(v, dict)]
        via_pkgs = [v for v in vuln.get("via", []) if isinstance(v, str)]
        titles = [a.get("title", "") for a in advisories]
        cwe = sorted({c for a in advisories for c in (a.get("cwe") or [])})
        refs = [a.get("url") for a in advisories if a.get("url")]

        if titles:
            title = f"Vulnerable dependency: {name} ({len(titles)} known issue(s))"
            desc = "\n".join(f"- {t}" for t in titles)
        else:
            title = f"Vulnerable dependency: {name} (via {', '.join(via_pkgs)})"
            desc = f"Inherits vulnerabilities from: {', '.join(via_pkgs)}"

        direct = bool(vuln.get("isDirect"))
        file = "package.json" if direct else "package-lock.json"
        line = find_line(root, file, f'"{name}"') if direct else find_line(root, file, f'node_modules/{name}"')

        fix = vuln.get("fixAvailable")
        if isinstance(fix, dict):
            hint = f"Update to {fix.get('name')}@{fix.get('version')}"
            if fix.get("isSemVerMajor"):
                hint += " (major version: test the app after updating)"
        elif fix is True:
            hint = "Fix available: run 'npm audit fix'"
        else:
            hint = "No automatic fix: replace the dependency or monitor it"

        findings.append(
            Finding(
                category="dependency",
                title=title,
                severity=SEVERITY_MAP.get(vuln.get("severity", "low"), "low"),
                file=file,
                line=line,
                snippet=read_snippet(root, file, line, context=0) if direct else None,
                description=desc + f"\nAffected versions: {vuln.get('range', '?')}"
                + ("" if direct else " (indirect dependency)"),
                cwe=cwe,
                package=name,
                fix_hint=hint,
                references=refs[:5],
                evidence=[Evidence(source=NAME, rule_id=",".join(r.split("/")[-1] for r in refs) or name, raw=vuln)],
            )
        )
    return findings
