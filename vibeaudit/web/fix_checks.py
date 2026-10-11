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
import re
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
        # Lockfile d'origine si on l'a : npm garde alors les versions transitives figées et le diff reste
        # minimal. Sinon on laisse npm en créer un neuf à partir de package.json (correctif quand même valide).
        if old_lock and old_lock.strip():
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


# ------------------------------------------------------------------ garde-fous
# Fichiers que l'IA n'a JAMAIS le droit d'écrire : ils sont calculés par le gestionnaire de paquets.
# (Constaté en test : l'IA a réécrit un package-lock.json de 623 lignes en 25, cassant l'installation.)
LOCKFILES = {"package-lock.json", "npm-shrinkwrap.json", "yarn.lock", "pnpm-lock.yaml", "bun.lockb",
             "poetry.lock", "Pipfile.lock", "composer.lock", "Gemfile.lock", "Cargo.lock", "go.sum"}

_OPEN = {"(": ")", "[": "]", "{": "}"}


def _balanced(code: str) -> bool:
    """Parenthèses / crochets / accolades équilibrés, en ignorant chaînes et commentaires (approximatif)."""
    stack: List[str] = []
    i, n = 0, len(code)
    while i < n:
        c = code[i]
        nxt = code[i + 1] if i + 1 < n else ""
        if c == "/" and nxt == "/":
            j = code.find("\n", i)
            i = n if j < 0 else j
            continue
        if c == "/" and nxt == "*":
            j = code.find("*/", i + 2)
            i = n if j < 0 else j + 2
            continue
        if c == "#" and (i == 0 or code[i - 1] == "\n"):  # commentaire Python / shell en début de ligne
            j = code.find("\n", i)
            i = n if j < 0 else j
            continue
        if c in "\"'`":
            q = c
            i += 1
            while i < n and code[i] != q:
                if code[i] == "\\":
                    i += 1
                elif q != "`" and code[i] == "\n":
                    break  # chaîne non fermée sur la ligne : on n'insiste pas
                i += 1
            i += 1
            continue
        if c in _OPEN:
            stack.append(_OPEN[c])
        elif c in ")]}":
            if not stack or stack.pop() != c:
                return False
        i += 1
    return not stack


def sanity_check(path: str, original: Optional[str], new: str) -> Optional[str]:
    """Vérifie qu'un fichier réécrit par l'IA n'est pas cassé. Retourne la raison du rejet, ou None si OK."""
    name = Path(path).name
    if name in LOCKFILES:
        return f"{name} is generated by the package manager and must never be edited by hand"
    if original and len(original) > 1500 and len(new) < 0.6 * len(original):
        return (f"{path} shrank from {len(original)} to {len(new)} characters: the file looks truncated "
                "(return the COMPLETE file)")
    ext = Path(path).suffix.lower()
    if ext == ".json":
        try:
            json.loads(new)
        except ValueError as e:
            return f"{path} is not valid JSON anymore ({str(e)[:80]})"
    elif ext == ".py":
        try:
            compile(new, path, "exec")
        except SyntaxError as e:
            return f"{path} has a Python syntax error at line {e.lineno}"
    elif ext in {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}:
        # On ne rejette que si l'original était équilibré et que la nouvelle version ne l'est plus
        if (original is None or _balanced(original)) and not _balanced(new):
            return f"{path} has unbalanced brackets: the file looks cut off or broken"
    return None


# ------------------------------------------------------------------ dépendances
_TARGET_RE = re.compile(r"(?:update|upgrade)\s+to\s+(@?[\w.\-/]+)@(\d[\w.\-+]*)", re.I)


def dependency_target(finding: Dict[str, Any]) -> Optional[Tuple[str, str, bool]]:
    """(paquet à mettre à jour, version cible, montée majeure ?) d'après la piste de correction du scanner.

    Pour une dépendance indirecte (ex. postcss via next), le paquet à mettre à jour est le parent (next).
    """
    hint = str(finding.get("fix_hint") or "")
    m = _TARGET_RE.search(hint)
    if m:
        return m.group(1), m.group(2), "major" in hint.lower()
    for ev in finding.get("evidence") or []:
        fix = ((ev or {}).get("raw") or {}).get("fixAvailable")
        if isinstance(fix, dict) and fix.get("name") and fix.get("version"):
            return str(fix["name"]), str(fix["version"]), bool(fix.get("isSemVerMajor"))
    return None


def bump_package_json(content: str, name: str, version: str) -> Tuple[Optional[str], str]:
    """Met `name` à `version` dans package.json (dependencies / devDependencies), en gardant le préfixe ^ ou ~."""
    try:
        data = json.loads(content)
    except ValueError:
        return None, "package.json is not valid JSON"
    for section in ("dependencies", "devDependencies", "optionalDependencies"):
        deps = data.get(section) or {}
        if name in deps:
            old = str(deps[name])
            prefix = old[0] if old[:1] in "^~" else ""
            deps[name] = prefix + version
            indent = 2
            m = re.search(r'\n( +)"', content)
            if m:
                indent = len(m.group(1))
            return json.dumps(data, indent=indent, ensure_ascii=False) + "\n", f"{name}: {old} -> {prefix}{version}"
    # Paquet indirect absent de package.json : on l'ajoute en "overrides" (npm >= 8.3)
    overrides = data.setdefault("overrides", {})
    overrides[name] = version
    return json.dumps(data, indent=2, ensure_ascii=False) + "\n", f"{name}: forced to {version} via overrides"


def audit_lockfile(package_json: str, lock: str, timeout: int = 180) -> Optional[Dict[str, Any]]:
    """npm audit sur un package.json + lockfile, sans rien installer. None si npm est indisponible."""
    if not shutil.which("npm"):
        return None
    with tempfile.TemporaryDirectory(prefix="va-audit-") as d:
        Path(d, "package.json").write_text(package_json, encoding="utf-8")
        Path(d, "package-lock.json").write_text(lock, encoding="utf-8")
        try:
            proc = subprocess.run(["npm", "audit", "--json", "--package-lock-only"], cwd=d,
                                  capture_output=True, text=True, timeout=timeout)
            data = json.loads(proc.stdout or "{}")
        except (subprocess.TimeoutExpired, OSError, json.JSONDecodeError):
            return None
    if "error" in data:
        return None
    return data.get("vulnerabilities") or {}


def npm_audit_fix(package_json: str, lock: str, timeout: int = 240,
                  force: bool = False) -> Tuple[Optional[str], Optional[str], str]:
    """`npm audit fix` sans rien installer ni exécuter : pour les dépendances dont le scanner ne donne pas
    de version cible. force=True ajoute --force (peut monter des versions majeures). Retour (package.json,
    lockfile, message), ou (None, None, raison)."""
    if not shutil.which("npm"):
        return None, None, "npm is not installed on the server"
    with tempfile.TemporaryDirectory(prefix="va-fix-") as d:
        Path(d, "package.json").write_text(package_json, encoding="utf-8")
        Path(d, "package-lock.json").write_text(lock, encoding="utf-8")
        cmd = ["npm", "audit", "fix", "--package-lock-only", "--ignore-scripts", "--no-fund"]
        if force:
            cmd.append("--force")
        try:
            subprocess.run(cmd, cwd=d, capture_output=True, text=True, timeout=timeout)
        except (subprocess.TimeoutExpired, OSError) as e:
            return None, None, f"npm audit fix did not finish ({type(e).__name__})"
        new_pj = Path(d, "package.json").read_text(encoding="utf-8")
        new_lock = Path(d, "package-lock.json").read_text(encoding="utf-8")
    if new_lock == lock and new_pj == package_json:
        return None, None, "npm audit fix found no compatible update"
    return new_pj, new_lock, "updated with npm audit fix"
