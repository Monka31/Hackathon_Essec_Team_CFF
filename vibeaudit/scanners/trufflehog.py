"""TruffleHog : détection de secrets (complémentaire à Gitleaks), avec notion de secret "vérifié".

TruffleHog teste si certains secrets sont encore valides (Verified). Un secret vérifié est
traité en gravité haute. On n'affiche jamais la valeur brute du secret.
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import List

from ..core.models import Evidence, Finding
from .base import ScannerError, read_snippet, require_binary, run_cmd, to_rel

NAME = "trufflehog"


def _detector(obj: dict) -> str:
    return obj.get("DetectorName") or obj.get("DetectorType") or "secret"


def _location(obj: dict):
    meta = (((obj.get("SourceMetadata") or {}).get("Data")) or {})
    fs = meta.get("Filesystem") or meta.get("Git") or {}
    f = fs.get("file")
    line = fs.get("line") or None
    try:
        line = int(line) if line else None
    except (TypeError, ValueError):
        line = None
    return f, line


def scan(root: Path, timeout: int = 600) -> List[Finding]:
    require_binary("trufflehog", "https://github.com/trufflesecurity/trufflehog")
    proc = run_cmd(
        ["trufflehog", "filesystem", ".", "--json", "--no-update"],
        cwd=root, timeout=timeout, ok_codes=(0, 183),  # 183 = des secrets trouvés
    )
    findings: List[Finding] = []
    seen = set()
    for raw in (proc.stdout or "").splitlines():
        raw = raw.strip()
        if not raw or not raw.startswith("{"):
            continue
        try:
            obj = json.loads(raw)
        except json.JSONDecodeError:
            continue
        if "DetectorName" not in obj and "SourceMetadata" not in obj:
            continue  # lignes de log, pas un résultat
        det = _detector(obj)
        rel, line = _location(obj)
        rel = to_rel(root, rel) if rel else None
        verified = bool(obj.get("Verified"))
        key = (det, rel, line)
        if key in seen:
            continue
        seen.add(key)
        sev = "high" if verified else "medium"
        findings.append(Finding(
            category="secret",
            title=f"Secret détecté ({det})" + (" — vérifié actif" if verified else ""),
            severity=sev,
            file=rel,
            line=line,
            snippet=read_snippet(root, rel, line) if rel and line else None,
            description=(f"TruffleHog a détecté un secret de type {det}. "
                         + ("Ce secret a été vérifié comme encore ACTIF : à révoquer et faire tourner en urgence."
                            if verified else
                            "Secret potentiel à vérifier manuellement, puis à révoquer et faire tourner s'il est réel.")),
            confidence="haute" if verified else "moyenne",
            fix_hint="Révoquer et régénérer ce secret, puis le charger depuis une variable d'environnement. "
                     "Le retirer du code ne suffit pas s'il reste valide ou présent dans l'historique.",
            evidence=[Evidence(source=NAME, rule_id=det, raw={"verified": verified})],
        ))
    return findings
