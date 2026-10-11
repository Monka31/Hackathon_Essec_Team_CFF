"""Contrôles des correctifs AVANT d'ouvrir la Pull Request.

1. verify_edits : relance Semgrep sur les seuls fichiers modifiés, version avant / version après.
   - la faille visée a-t-elle disparu ?
   - le correctif a-t-il introduit une NOUVELLE faille ?
   Un correctif qui échoue à ce contrôle n'est jamais proposé tel quel.
2. regen_lockfile : un correctif de dépendance qui ne touche que package.json ne corrige rien,
   car npm audit lit package-lock.json. On régénère donc le lockfile (sans rien exécuter du projet).

Aucun code du projet audité n'est exécuté : Semgrep lit le code, npm ne fait que résoudre les versions
(--package-lock-only --ignore-scripts).
"""
from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set, Tuple

# Extensions que Semgrep sait analyser ici (les autres fichiers modifiés ne sont pas re-scannés)
_CODE_EXT = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs", ".py", ".vue", ".svelte", ".html",
             ".java", ".go", ".rb", ".php", ".yml", ".yaml", ".json", ".tf", ".sh"}


def _write_tree(base: Path, files: Dict[str, Optional[str]]) -> int:
    n = 0
    for rel, content in files.items():
        if content is None or Path(rel).suffix.lower() not in _CODE_EXT and Path(rel).name != "Dockerfile":
            continue
        dest = (base / rel).resolve()
        dest.relative_to(base.resolve())  # jamais en dehors du dossier temporaire
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_text(content, encoding="utf-8")
        n += 1
    return n


def _semgrep(base: Path, timeout: int = 240) -> Optional[Set[Tuple[str, str, str]]]:
    """Ensemble (fichier, règle, ligne de code normalisée) ; None si Semgrep est indisponible ou plante."""
    from ..scanners import semgrep as sg

    if not shutil.which("semgrep"):
        return None
    cmd = ["semgrep", "scan", "--json", "--quiet", "--metrics=off", "--timeout", "30"]
    for c in sg.configs():
        cmd += ["--config", c]
    cmd.append(".")
    try:
        proc = subprocess.run(cmd, cwd=str(base), capture_output=True, text=True, timeout=timeout)
        data = json.loads(proc.stdout or "{}")
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError):
        return None
    out: Set[Tuple[str, str, str]] = set()
    cache: Dict[str, List[str]] = {}
    for r in data.get("results", []):
        rel = str(r.get("path", ""))
        rel = rel[2:] if rel.startswith("./") else rel
        if rel not in cache:
            try:
                cache[rel] = (base / rel).read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                cache[rel] = []
        n = int((r.get("start") or {}).get("line") or 0)
        lines = cache[rel]
        # Le texte de la ligne, lu dans le fichier (le champ 'lines' de Semgrep peut être masqué)
        code = " ".join(lines[n - 1].split()) if 0 < n <= len(lines) else ""
        out.add((rel, str(r.get("check_id", "")), code))
    return out


def _short_rule(rule: str) -> str:
    return rule.split(".")[-1]


def verify_edits(finding: Dict[str, Any], before: Dict[str, Optional[str]],
                 edits: List[Dict[str, str]]) -> Dict[str, Any]:
    """Compare Semgrep avant/après sur les fichiers modifiés.

    Retour : {checked, resolved (True/False/None si non vérifiable), introduced: [règles], reason}
    """
    after = {e["path"]: e["new_content"] for e in edits}
    old_files = {p: before.get(p) for p in after}
    with tempfile.TemporaryDirectory(prefix="va-old-") as d_old, \
            tempfile.TemporaryDirectory(prefix="va-new-") as d_new:
        if _write_tree(Path(d_new), after) == 0:
            return {"checked": False, "resolved": None, "introduced": [], "reason": "no code file changed"}
        _write_tree(Path(d_old), old_files)
        res_old = _semgrep(Path(d_old))
        res_new = _semgrep(Path(d_new))
    if res_old is None or res_new is None:
        return {"checked": False, "resolved": None, "introduced": [], "reason": "semgrep unavailable"}

    # Nouvelles failles : règle + ligne de code absentes de la version d'origine du même fichier
    old_keys = {(f, rule, code) for f, rule, code in res_old}
    introduced = sorted({_short_rule(rule) for f, rule, code in res_new if (f, rule, code) not in old_keys})

    # Faille visée : vérifiable seulement si c'est une règle Semgrep et que son fichier a été modifié
    rule = str(finding.get("rule_id") or ((finding.get("evidence") or [{}])[0] or {}).get("rule_id") or "")
    target_file = finding.get("file") or ""
    resolved: Optional[bool] = None
    if "." in rule and target_file in after:
        was_there = any(f == target_file and r == rule for f, r, _ in res_old)
        if was_there:
            resolved = not any(f == target_file and r == rule for f, r, _ in res_new)

    reasons = []
    if resolved is False:
        reasons.append(f"the rule '{_short_rule(rule)}' still matches in {target_file}")
    if introduced:
        reasons.append("the change introduces new issue(s): " + ", ".join(introduced[:5]))
    return {"checked": True, "resolved": resolved, "introduced": introduced, "reason": "; ".join(reasons)}


def regen_lockfile(package_json: str, old_lock: str, timeout: int = 240) -> Tuple[Optional[str], str]:
    """Recalcule package-lock.json pour un package.json modifié. Retour (nouveau lockfile ou None, message)."""
    if not shutil.which("npm"):
        return None, "npm is not installed on the server"
    with tempfile.TemporaryDirectory(prefix="va-lock-") as d:
        Path(d, "package.json").write_text(package_json, encoding="utf-8")
        Path(d, "package-lock.json").write_text(old_lock, encoding="utf-8")
        try:
            proc = subprocess.run(
                ["npm", "install", "--package-lock-only", "--ignore-scripts", "--no-audit", "--no-fund"],
                cwd=d, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as e:
            return None, f"npm did not finish ({type(e).__name__})"
        if proc.returncode != 0:
            tail = " | ".join((proc.stderr or proc.stdout or "").strip().splitlines()[-2:])
            return None, f"npm could not resolve the new versions: {tail[:200]}"
        new_lock = Path(d, "package-lock.json").read_text(encoding="utf-8")
    return new_lock, "package-lock.json regenerated"
