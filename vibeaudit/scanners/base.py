"""Outils communs aux scanners."""
from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path
from typing import List, Optional, Tuple


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
