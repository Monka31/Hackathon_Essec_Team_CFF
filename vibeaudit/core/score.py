"""Score de sécurité sur 100 (choix D)."""
from __future__ import annotations

from typing import Dict, List

from .models import SEVERITIES, Finding

PENALTIES = {"critical": 25, "high": 10, "medium": 3, "low": 1}
# Plafond de pénalité par catégorie : un seul type de problème (ex : dépendances) ne peut pas,
# à lui seul, mettre le score à zéro. Un projet au code propre mais aux dépendances à jour de rien
# garde ainsi un score parlant au lieu de 0.
import os as _os
CATEGORY_CAP = int(_os.getenv("SCORE_CATEGORY_CAP", "40"))


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def compute_score(findings: List[Finding]) -> int:
    per_cat: Dict[str, int] = {}
    for f in findings:
        per_cat[f.category] = per_cat.get(f.category, 0) + PENALTIES.get(f.severity, 0)
    penalty = sum(min(CATEGORY_CAP, p) for p in per_cat.values())
    return max(0, 100 - penalty)


def grade(score: int) -> str:
    if score >= 90:
        return "A"
    if score >= 75:
        return "B"
    if score >= 50:
        return "C"
    if score >= 25:
        return "D"
    return "E"
