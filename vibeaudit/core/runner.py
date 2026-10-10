"""Lance les scanners en parallèle, normalise, masque, fusionne et note."""
from __future__ import annotations

import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

from .. import __version__
from ..scanners import LABELS, SCANNERS, gitleaks
from ..scanners.base import ScannerError, ScannerSkipped
from .merge import merge_findings
from .models import Finding, ScannerRun
from .redact import Redactor
from .score import PENALTIES, compute_score, count_by_severity, grade


def _run_one(name: str, root: Path) -> ScannerRun:
    run = ScannerRun(name=name)
    t0 = time.time()
    try:
        run.findings = SCANNERS[name](root)
        run.message = f"{len(run.findings)} résultat(s)"
    except ScannerSkipped as e:
        run.status, run.message = "skipped", str(e)
    except ScannerError as e:
        run.status, run.message = "error", str(e)
    except Exception as e:  # un scanner qui plante ne bloque jamais les autres (choix G)
        run.status, run.message = "error", f"{type(e).__name__}: {e}"[:300]
    run.duration_s = time.time() - t0
    return run


def audit(target: Path, only: Optional[Iterable[str]] = None, skip: Optional[Iterable[str]] = None) -> Dict[str, Any]:
    root = target.resolve()
    names = [n for n in SCANNERS if (not only or n in only) and (not skip or n not in skip)]

    with ThreadPoolExecutor(max_workers=len(names) or 1) as pool:
        runs: List[ScannerRun] = list(pool.map(lambda n: _run_one(n, root), names))

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

    return {
        "tool": "vibeaudit",
        "version": __version__,
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "target": root.name,
        "score": score,
        "grade": grade(score),
        "score_rule": PENALTIES,
        "counts": count_by_severity(findings),
        "total": len(findings),
        "raw_total": len(all_findings),
        "scanners": [dict(r.to_dict(), label=LABELS.get(r.name, r.name)) for r in runs],
        "findings": [f.to_dict() for f in findings],
    }
