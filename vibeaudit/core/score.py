"""Score de sécurité sur 100 (choix D)."""
from __future__ import annotations

from typing import Dict, List

from .models import SEVERITIES, Finding

PENALTIES = {"critical": 25, "high": 10, "medium": 3, "low": 1}


def count_by_severity(findings: List[Finding]) -> Dict[str, int]:
    counts = {s: 0 for s in SEVERITIES}
    for f in findings:
        if f.severity in counts:
            counts[f.severity] += 1
    return counts


def compute_score(findings: List[Finding]) -> int:
    penalty = sum(PENALTIES.get(f.severity, 0) for f in findings)
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
