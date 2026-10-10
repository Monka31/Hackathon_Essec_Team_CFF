"""Gitleaks : secrets (clés API, tokens) dans le code ET dans l'historique git."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import List

from ..core.models import Evidence, Finding
from .base import read_snippet, require_binary, run_cmd, to_rel

NAME = "gitleaks"

# Clés publiques par conception : visibles côté navigateur, ce n'est pas une fuite en soi.
# On les garde dans le rapport (en "basse") car toute la sécurité repose alors sur d'autres règles (RLS...).
PUBLIC_KEY_PREFIXES = ("sb_publishable_", "pk_live_", "pk_test_")


def _is_public_key(secret: str) -> bool:
    if secret.startswith(PUBLIC_KEY_PREFIXES):
        return True
    if secret.startswith("eyJ") and secret.count(".") == 2:
        import base64, json as _json
        try:
            payload = secret.split(".")[1]
            payload += "=" * (-len(payload) % 4)
            return _json.loads(base64.urlsafe_b64decode(payload)).get("role") == "anon"
        except Exception:
            return False
    return False


def scan(root: Path, timeout: int = 600) -> List[Finding]:
    require_binary("gitleaks", "brew install gitleaks")
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp) / "gitleaks.json"
        cmd = [
            "gitleaks", "detect", "--source", ".", "--report-format", "json",
            "--report-path", str(report), "--no-banner", "--exit-code", "0",
        ]
        if not (root / ".git").exists():
            cmd.append("--no-git")  # pas de repo git : on scanne seulement les fichiers
        run_cmd(cmd, cwd=root, timeout=timeout)
        data = json.loads(report.read_text() or "[]") if report.exists() else []

    findings: List[Finding] = []
    for leak in data or []:
        rel = to_rel(root, leak.get("File", ""))
        line = leak.get("StartLine")
        in_history = bool(leak.get("Commit"))
        still_present = (root / rel).exists()
        where = []
        if still_present:
            where.append("présent dans le code actuel")
        if in_history:
            where.append(f"présent dans l'historique git (commit {leak['Commit'][:8]})")
        public = _is_public_key(leak.get("Secret", ""))
        if public:
            findings.append(
                Finding(
                    category="secret",
                    title="Clé publique dans le code (normal, à vérifier)",
                    severity="low",
                    file=rel,
                    line=line,
                    snippet=read_snippet(root, rel, line) if still_present else None,
                    description=("Clé publique par conception (Supabase publishable/anon, Stripe publishable). "
                                 "Ce n'est pas une fuite, mais toute la sécurité repose alors sur les règles d'accès "
                                 "(RLS de chaque table Supabase)."),
                    fix_hint="Vérifier que la RLS est activée sur toutes les tables (Supabase > Advisors > Security).",
                    evidence=[Evidence(source=NAME, rule_id=leak.get("RuleID", ""), raw=leak)],
                )
            )
            continue
        findings.append(
            Finding(
                category="secret",
                title=f"Secret exposé : {leak.get('RuleID', 'secret')}",
                severity="critical",  # choix C : tout secret est critique
                file=rel,
                line=line,
                snippet=read_snippet(root, rel, line) if still_present else None,
                description=(leak.get("Description", "") + " (" + ", ".join(where) + ")").strip(),
                cwe=["CWE-798"],
                fix_hint=(
                    "Révoquer la clé chez le fournisseur et en générer une nouvelle, la sortir du code "
                    "(variable d'environnement côté serveur), puis nettoyer l'historique git si besoin."
                ),
                evidence=[Evidence(source=NAME, rule_id=leak.get("RuleID", ""), raw=leak)],
            )
        )
    return findings


def known_secrets(findings: List[Finding]) -> List[str]:
    """Valeurs exactes des secrets trouvés, pour les masquer partout dans le rapport."""
    out = []
    for f in findings:
        for e in f.evidence:
            if e.source == NAME:
                out += [e.raw.get("Secret", ""), e.raw.get("Match", "")]
    return [s for s in out if s]
