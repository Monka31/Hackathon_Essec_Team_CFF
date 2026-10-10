"""Fusion des doublons entre scanners (choix E)."""
from __future__ import annotations

from typing import Dict, List

from .models import Finding, severity_rank


def merge_findings(findings: List[Finding]) -> List[Finding]:
    merged: Dict[tuple, Finding] = {}
    for f in findings:
        key = f.merge_key
        if key not in merged:
            merged[key] = f
            continue
        m = merged[key]
        # On garde la gravité la plus haute et le titre qui va avec
        if severity_rank(f.severity) < severity_rank(m.severity):
            m.severity = f.severity
            m.title = f.title
        m.evidence.extend(f.evidence)
        m.cwe = sorted(set(m.cwe) | set(f.cwe))
        m.references = list(dict.fromkeys(m.references + f.references))
        if not m.snippet and f.snippet:
            m.snippet = f.snippet
        if not m.fix_hint and f.fix_hint:
            m.fix_hint = f.fix_hint
        if f.description and f.description not in m.description:
            m.description = (m.description + "\n" + f.description).strip()

    return sorted(
        merged.values(),
        key=lambda x: (severity_rank(x.severity), x.category, x.file or "", x.line or 0),
    )
