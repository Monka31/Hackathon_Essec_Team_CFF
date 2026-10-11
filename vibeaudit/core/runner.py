"""Lance les scanners en parallèle, normalise, masque, fusionne et note."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Dict, Iterable, List, Optional

from .. import __version__
from ..scanners import LABELS, SCANNERS, URL_SCANNERS, gitleaks
from ..scanners.base import ScannerError, ScannerSkipped, is_excluded
from .merge import merge_findings
from .models import Finding, ScannerRun
from .redact import Redactor
from .score import PENALTIES, compute_score, count_by_severity, grade

Progress = Optional[Callable[[str, str, str], None]]  # (scanner, statut, message)


def _run_one(name: str, fn: Callable[[], List[Finding]], progress: Progress = None) -> ScannerRun:
    run = ScannerRun(name=name)
    if progress:
        progress(name, "running", "en cours")
    t0 = time.time()
    try:
        result = fn()
        run.findings = list(result)
        note = getattr(result, "note", "")
        run.message = f"{len(run.findings)} résultat(s)" + (f", {note}" if note else "")
    except ScannerSkipped as e:
        run.status, run.message = "skipped", str(e)
    except ScannerError as e:
        run.status, run.message = "error", str(e)
    except Exception as e:  # un scanner qui plante ne bloque jamais les autres (choix G)
        run.status, run.message = "error", f"{type(e).__name__}: {e}"[:300]
    run.duration_s = time.time() - t0
    if progress:
        progress(name, run.status, run.message)
    return run


def selected(names: Iterable[str], only=None, skip=None) -> List[str]:
    return [n for n in names if (not only or n in only) and (not skip or n not in skip)]


def run_repo_scanners(root: Path, only=None, skip=None, progress: Progress = None) -> List[ScannerRun]:
    names = selected(SCANNERS, only, skip)
    with ThreadPoolExecutor(max_workers=len(names) or 1) as pool:
        runs = list(pool.map(lambda n: _run_one(n, lambda: SCANNERS[n](root), progress), names))
    for run in runs:
        kept = [f for f in run.findings if not is_excluded(f.file, f.category)]
        dropped = len(run.findings) - len(kept)
        if dropped:
            run.findings = kept
            run.message += f" ; {dropped} ignoré(s), {len(kept)} retenu(s) (code généré, dépendances installées, tests ou notes de correctif)"
    return runs


def run_url_scanners(url: str, only=None, skip=None, progress: Progress = None) -> List[ScannerRun]:
    names = selected(URL_SCANNERS, only, skip)
    return [_run_one(n, lambda n=n: URL_SCANNERS[n](url), progress) for n in names]


def build_report(runs: List[ScannerRun], meta: Dict[str, Any]) -> Dict[str, Any]:
    all_findings: List[Finding] = [f for r in runs for f in r.findings]

    # Masquage des secrets partout : extraits, descriptions, preuves brutes (choix F)
    redactor = Redactor()
    redactor.add(gitleaks.known_secrets(all_findings))
    for f in all_findings:
        f.snippet = redactor.text(f.snippet) if f.snippet else f.snippet
        f.description = redactor.text(f.description)
        for e in f.evidence:
            e.raw = redactor.deep(e.raw)

    findings = merge_findings(all_findings)
    score = compute_score(findings)
    report = {
        "tool": "vibeaudit",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": meta.get("target", ""),
        "repo_url": meta.get("repo_url"),
        "app_url": meta.get("app_url"),
        "score": score,
        "grade": grade(score),
        "score_rule": PENALTIES,
        "counts": count_by_severity(findings),
        "total": len(findings),
        "raw_total": len(all_findings),
        "scanners": [dict(r.to_dict(), label=LABELS.get(r.name, r.name)) for r in runs],
        "findings": [f.to_dict() for f in findings],
        "_findings": findings,  # objets, retirés avant écriture
    }
    return report


def audit(target: Optional[Path] = None, url: Optional[str] = None, only=None, skip=None,
          progress: Progress = None) -> Dict[str, Any]:
    """Audit complet en ligne de commande (dossier local et/ou URL)."""
    runs: List[ScannerRun] = []
    if target:
        runs += run_repo_scanners(target.resolve(), only, skip, progress)
    if url:
        runs += run_url_scanners(url, only, skip, progress)
    report = build_report(runs, {"target": target.resolve().name if target else url, "app_url": url})
    report.pop("_findings", None)
    return report
