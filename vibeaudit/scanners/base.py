"""Outils communs aux scanners."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


# Dossiers jamais audités : code généré, dépendances installées, caches d'outils.
# Les y laisser fait remonter des doublons du vrai code et du bruit qui ne se corrige pas.
EXCLUDED_DIRS = {
    "node_modules", ".next", ".nuxt", ".svelte-kit", ".vercel", ".turbo", "dist", "build", "out",
    "coverage", "vendor", ".venv", "venv", "__pycache__", ".git", "graphify-out",
}
# Dossiers de tests : ignorés pour les failles de code (fausses entrées volontaires),
# mais PAS pour les secrets (une vraie clé dans un test reste une vraie fuite).
TEST_DIRS = {"test", "tests", "__tests__", "__mocks__", "fixtures", "e2e", "cypress"}
# Fichiers écrits par nos propres Pull Requests de correction : ils citent les failles corrigées.
EXCLUDED_FILES = ("SECURITY_FIXES*.md",)


def is_excluded(rel_path: Optional[str], category: str = "") -> bool:
    """Vrai si la faille vient d'un fichier qu'on ne doit pas auditer."""
    import fnmatch

    if not rel_path or "://" in rel_path or rel_path.startswith("supabase:"):
        return False
    parts = Path(rel_path).parts
    extra = {d.strip() for d in os.getenv("VIBEAUDIT_EXCLUDE_DIRS", "").split(",") if d.strip()}
    if any(p in EXCLUDED_DIRS or p in extra for p in parts[:-1]):
        return True
    if any(fnmatch.fnmatch(parts[-1], pat) for pat in EXCLUDED_FILES):
        return True
    if category != "secret" and any(p.lower() in TEST_DIRS for p in parts[:-1]):
        return True
    return False


class ScannerSkipped(Exception):
    """Le scanner ne peut pas tourner (outil absent, token manquant...). Ce n'est pas une erreur."""


class ScannerError(Exception):
    """Le scanner a tourné mais a échoué."""


def require_binary(name: str, install_hint: str) -> str:
    path = shutil.which(name)
    if not path:
        raise ScannerSkipped(f"'{name}' n'est pas installé ({install_hint})")
    return path


def run_cmd(
    cmd: List[str],
    cwd: Path,
    timeout: int = 600,
    ok_codes: Tuple[int, ...] = (0,),
    env_extra: Optional[dict] = None,
) -> subprocess.CompletedProcess:
    env = dict(os.environ)
    if env_extra:
        env.update({k: v for k, v in env_extra.items() if v})
    try:
        proc = subprocess.run(
            cmd, cwd=str(cwd), capture_output=True, text=True, timeout=timeout, env=env
        )
    except subprocess.TimeoutExpired:
        raise ScannerError(f"délai dépassé ({timeout} s)")
    if proc.returncode not in ok_codes:
        err = (proc.stderr or proc.stdout or "").strip().splitlines()
        raise ScannerError(f"code {proc.returncode} : " + " | ".join(err[-3:])[:400])
    return proc


def read_snippet(root: Path, rel_path: Optional[str], line: Optional[int], context: int = 2) -> Optional[str]:
    """Extrait les lignes autour de la faille, numérotées, directement depuis le fichier."""
    if not rel_path or not line:
        return None
    p = (root / rel_path).resolve()
    try:
        p.relative_to(root.resolve())  # on ne lit jamais en dehors du projet
        lines = p.read_text(encoding="utf-8", errors="replace").splitlines()
    except (OSError, ValueError):
        return None
    start = max(1, line - context)
    end = min(len(lines), line + context)
    width = len(str(end))
    out = []
    for i in range(start, end + 1):
        marker = ">" if i == line else " "
        out.append(f"{marker} {str(i).rjust(width)} | {lines[i - 1][:200]}")
    return "\n".join(out)


def find_line(root: Path, rel_path: str, needle: str) -> Optional[int]:
    """Numéro de la première ligne contenant `needle` (pour situer une dépendance dans package.json)."""
    try:
        for i, l in enumerate((root / rel_path).read_text(encoding="utf-8").splitlines(), 1):
            if needle in l:
                return i
    except OSError:
        pass
    return None


def to_rel(root: Path, path: str) -> str:
    p = Path(path)
    if p.is_absolute():
        try:
            return str(p.resolve().relative_to(root.resolve()))
        except ValueError:
            return str(p)
    s = str(path)
    return s[2:] if s.startswith("./") else s
