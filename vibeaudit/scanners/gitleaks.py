"""Gitleaks : secrets (clés API, tokens) dans le code ET dans l'historique git."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path
from typing import List

from ..core.models import Evidence, Finding
from .base import find_line, read_snippet, require_binary, run_cmd, to_rel

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
        secret = leak.get("Secret", "") or ""
        in_history = bool(leak.get("Commit"))
        # La clé est-elle encore DANS le fichier actuel ? (et pas seulement : le fichier existe-t-il ?)
        line = find_line(root, rel, secret) if secret and (root / rel).is_file() else None
        still_present = line is not None
        if not still_present and not in_history:
            line = leak.get("StartLine")  # scan sans git : on garde la position donnée par gitleaks
            still_present = (root / rel).is_file()
        public = _is_public_key(secret)
        rule = leak.get("RuleID", "secret")
        ev = [Evidence(source=NAME, rule_id=rule, raw=leak)]

        if public:
            if not still_present:
                continue  # clé publique par conception, retirée du code : rien à signaler
            findings.append(
                Finding(
                    category="secret",
                    title="Public key in the code (expected, verify RLS)",
                    severity="low",
                    file=rel,
                    line=line,
                    snippet=read_snippet(root, rel, line),
                    description=("Public key by design (Supabase publishable/anon, Stripe publishable). "
                                 "Not a leak in itself, but all security then rests on the access rules "
                                 "(row level security of each Supabase table)."),
                    fix_hint="Check that row level security is enabled on every table (Supabase > Advisors > Security).",
                    evidence=ev,
                )
            )
            continue

        if still_present:
            findings.append(
                Finding(
                    category="secret",
                    title=f"Exposed secret: {rule}",
                    severity="critical",  # choix C : tout secret présent dans le code est critique
                    file=rel,
                    line=line,
                    snippet=read_snippet(root, rel, line),
                    description=(leak.get("Description", "") + " (present in the current code)").strip(),
                    cwe=["CWE-798"],
                    fix_hint=(
                        "Revoke the key at the provider and generate a new one, then move it out of the code "
                        "(server-side environment variable)."
                    ),
                    evidence=ev,
                )
            )
        else:
            # Retirée du code mais toujours lisible dans l'historique git : le seul vrai correctif
            # est de révoquer la clé (réécrire l'historique ne suffit pas, il a pu être copié).
            findings.append(
                Finding(
                    category="secret",
                    title=f"Secret removed from the code but still in git history: {rule}",
                    severity="high",
                    file=rel,
                    line=None,
                    snippet=None,
                    description=(leak.get("Description", "") +
                                 f" (no longer in the current code, still readable in commit {leak['Commit'][:8]})").strip(),
                    cwe=["CWE-798"],
                    fix_hint=(
                        "Revoke this key at the provider. Once revoked, the old value in the history is harmless. "
                        "Rewriting git history is optional and does not replace revocation."
                    ),
                    evidence=ev,
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
