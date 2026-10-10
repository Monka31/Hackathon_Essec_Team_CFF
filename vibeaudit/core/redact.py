"""Masquage des secrets (choix F) : notre propre rapport ne doit jamais devenir une fuite."""
from __future__ import annotations

import math
import re
from typing import Any, Iterable, Set

KEEP = 4  # nombre de caractères visibles

# Filet de sécurité : longues chaînes qui ressemblent à des clés ou des jetons
_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9])([A-Za-z0-9_\-+/=.]{24,})(?![A-Za-z0-9])")
_PREFIXED_RE = re.compile(
    r"\b((?:sk|pk|rk)_(?:live|test)_[A-Za-z0-9]{8,}|gh[pousr]_[A-Za-z0-9]{20,}|AKIA[0-9A-Z]{16}|xox[baprs]-[A-Za-z0-9-]{10,}|eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,})"
)


def mask(secret: str) -> str:
    if not secret:
        return secret
    return secret[:KEEP] + "•" * 8 + f" ({len(secret)} car.)"


_HEX_RE = re.compile(r"^[0-9a-f]{40}$|^[0-9a-f]{64}$")  # SHA de commit : pas un secret


def _entropy(s: str) -> float:
    counts = {c: s.count(c) for c in set(s)}
    return -sum(n / len(s) * math.log2(n / len(s)) for n in counts.values())


def _looks_like_token(s: str) -> bool:
    """Une chaîne longue, avec lettres et chiffres, aléatoire, et qui n'est pas un chemin."""
    if s.startswith("eyJ"):
        return True
    if "/" in s or _HEX_RE.match(s):
        return False
    has_digit = any(c.isdigit() for c in s)
    has_alpha = any(c.isalpha() for c in s)
    return has_digit and has_alpha and _entropy(s) > 4.0


class Redactor:
    def __init__(self) -> None:
        self.known: Set[str] = set()

    def add(self, secrets: Iterable[str]) -> None:
        for s in secrets:
            if s and len(s) >= 6:
                self.known.add(s)

    def text(self, value: str) -> str:
        if not value:
            return value
        out = value
        for s in sorted(self.known, key=len, reverse=True):
            out = out.replace(s, mask(s))
        out = _PREFIXED_RE.sub(lambda m: mask(m.group(1)), out)
        out = _TOKEN_RE.sub(
            lambda m: mask(m.group(1)) if _looks_like_token(m.group(1)) else m.group(1), out
        )
        return out

    def deep(self, obj: Any) -> Any:
        """Masque récursivement dans une structure JSON (sortie brute d'un scanner)."""
        if isinstance(obj, str):
            return self.text(obj)
        if isinstance(obj, list):
            return [self.deep(x) for x in obj]
        if isinstance(obj, dict):
            out = {}
            for k, v in obj.items():
                if k.lower() in ("secret", "match") and isinstance(v, str):
                    out[k] = mask(v)
                else:
                    out[k] = self.deep(v)
            return out
        return obj
