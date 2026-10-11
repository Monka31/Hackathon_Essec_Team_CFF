"""Comparaison d'un audit avec le précédent audit du même projet.

Les failles sont rapprochées par leur empreinte stable (core.models.fingerprint), pas par leur
numéro de ligne : un correctif qui décale le code ne fait donc pas apparaître de « nouvelles » failles.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional, Set

from .models import fingerprint_of

# Champs conservés pour afficher une faille corrigée (on ne recopie pas tout l'ancien rapport)
_KEEP = ("id", "category", "title", "severity", "file", "line", "snippet", "description", "cwe",
         "package", "evidence", "sources", "explanations", "fix_steps")


def compare(previous: Dict[str, Any], findings: List[Dict[str, Any]],
            ran_ok: Optional[Set[str]] = None) -> Dict[str, Any]:
    """previous = rapport JSON de l'audit précédent ; findings = failles (dict) du nouvel audit ;
    ran_ok = scanners qui ont réellement tourné cette fois.

    Marque chaque nouvelle faille avec 'change' = 'new' | 'persisting', et renvoie le bilan.
    Une ancienne faille n'est déclarée « corrigée » que si un des scanners qui l'avaient trouvée
    a bien tourné cette fois (sinon elle est « non revérifiée », jamais comptée comme corrigée).
    """
    old = {fingerprint_of(f): f for f in previous.get("findings", [])}
    seen = set()
    new_count = persisting = 0
    for f in findings:
        key = fingerprint_of(f)
        if key in old:
            f["change"] = "persisting"
            persisting += 1
            seen.add(key)
        else:
            f["change"] = "new"
            new_count += 1
    fixed, unchecked = [], 0
    for key, f in old.items():
        if key in seen:
            continue
        sources = set(f.get("sources") or [])
        if ran_ok is not None and sources and not (sources & ran_ok):
            unchecked += 1  # le scanner qui l'avait trouvée n'a pas tourné : on ne sait pas
            continue
        fixed.append({k: v for k, v in f.items() if k in _KEEP})
    return {
        "previous_job_id": previous.get("job_id"),
        "previous_generated_at": previous.get("generated_at"),
        "previous_score": previous.get("score"),
        "fixed_count": len(fixed),
        "persisting_count": persisting,
        "new_count": new_count,
        "unchecked_count": unchecked,
        "fixed": fixed,
    }


def same_scope(previous: Dict[str, Any], current_scanners: List[Dict[str, Any]]) -> Optional[str]:
    """Signale si les deux audits n'ont pas fait tourner les mêmes scanners (comparaison à nuancer)."""
    prev = {s.get("name") for s in previous.get("scanners", []) if s.get("status") == "ok"}
    cur = {s.get("name") for s in current_scanners if s.get("status") == "ok"}
    if not prev or prev == cur:
        return None
    added, removed = sorted(cur - prev), sorted(prev - cur)
    parts = []
    if added:
        parts.append("scanners added since last audit: " + ", ".join(added))
    if removed:
        parts.append("scanners that did not run this time: " + ", ".join(removed))
    return "; ".join(parts)
