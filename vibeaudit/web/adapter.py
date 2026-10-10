"""Traduit le rapport interne vers le format attendu par le prototype (le [CONTRACT] de l'interface)."""
from __future__ import annotations

import re
import re
from typing import Any, Dict, List

# clés internes (FR) -> clés de l'interface (EN)
LEVEL_MAP = {"debutant": "beginner", "intermediaire": "intermediate", "avance": "advanced", "expert": "expert"}
CONF_MAP = {"haute": "high", "moyenne": "medium", "faible": "low"}
CATEGORY_EN = {"code": "Code", "dependency": "Vulnerable dependency", "secret": "Exposed secret",
               "config": "Database / configuration", "web": "Online app"}
LAYER = {"code": "application", "dependency": "supply chain", "secret": "frontend",
         "config": "database", "web": "online app"}
OWASP = {"code": "OWASP A03", "dependency": "OWASP A06", "secret": "OWASP A07",
         "config": "OWASP A01", "web": "OWASP A05"}

_SNIP = re.compile(r"^(>?)\s*(\d+)\s*\|\s?(.*)$")


def _code(snippet: str | None) -> List[Dict[str, Any]]:
    if not snippet:
        return []
    out = []
    for line in snippet.splitlines():
        m = _SNIP.match(line)
        if m:
            out.append({"n": int(m.group(2)), "text": m.group(3), "hit": m.group(1) == ">"})
    return out


def _explanations(f: Dict[str, Any]) -> Dict[str, str]:
    raw = f.get("explanations") or {}
    out = {}
    for fr, en in LEVEL_MAP.items():
        if raw.get(fr):
            out[en] = raw[fr]
    return out


def _finding(f: Dict[str, Any]) -> Dict[str, Any]:
    cat = f.get("category", "code")
    expl = _explanations(f)
    sources = f.get("sources") or []
    cross = len(sources) > 1
    return {
        "id": f["id"],
        "severity": f.get("severity", "medium"),
        "title": f.get("title", ""),
        # founder language
        "impact": expl.get("beginner") or (f.get("description") or "").split("\n")[0][:300],
        "who_can_exploit": f.get("attack_scenario") or "An attacker able to reach this part of your app.",
        # developer fields
        "rule_id": (f.get("evidence") or [{}])[0].get("rule_id") or cat,
        "category": CATEGORY_EN.get(cat, cat),
        "owasp": OWASP.get(cat, ""),
        "cwe": ", ".join(f.get("cwe") or []) or "n/a",
        "layer": LAYER.get(cat, cat),
        "confidence": CONF_MAP.get(f.get("confidence") or "", "medium"),
        "file": f.get("file") or "",
        "line": f.get("line"),
        "technical_detail": f.get("title", ""),
        "summary": (f.get("description") or "")[:1200],
        "code": _code(f.get("snippet")),
        "proof": {
            "confirmed": cross,
            "text": ("confirmed by two independent scanners (" + ", ".join(sources) + ")")
                     if cross else ("detected by " + (sources[0] if sources else "scanner")
                                    + " (static analysis, not an active attack test)"),
        },
        "fix_status": "open",
        "pr_url": None,
        # 4 niveaux pour le sélecteur
        "explanations": expl,
        "fix_steps": f.get("fix_steps") or [],
    }


def to_prototype(report: Dict[str, Any]) -> Dict[str, Any]:
    findings = report.get("findings", [])
    main, ignored = [], []
    for f in findings:
        if f.get("ai_verdict") == "false_positive_suspected":
            ignored.append({
                "rule_id": (f.get("evidence") or [{}])[0].get("rule_id") or f.get("category", ""),
                "location": f"{f.get('file', '')}{':' + str(f['line']) if f.get('line') else ''}",
                "reason": f.get("confidence_reason") or f.get("attack_scenario") or "Likely not exploitable here.",
            })
        else:
            main.append(_finding(f))
    target = report.get("app_url") or report.get("repo_url") or report.get("target") or ""
    return {
        "audit_id": report.get("job_id") or report.get("target", ""),
        "project": report.get("target", "project"),
        "target": target,
        "type": "deep" if report.get("repo_url") else "quick",
        "scanned_at": report.get("generated_at"),
        "commit": None,
        "ai": report.get("ai"),
        "ai_summary": report.get("ai_summary"),
        "findings": main,
        "ignored": ignored,
    }


STEP_EN = {"clone": "Cloning the GitHub repo", "snyk_code": "Snyk Code (code)",
           "snyk_deps": "Snyk Open Source (dependencies)", "semgrep": "Semgrep (code)",
           "gitleaks": "Gitleaks (secrets)", "npm_audit": "npm audit (dependencies)",
           "supabase": "Supabase Advisor (database)", "web_passive": "Passive tests (online app)",
           "snyk_dast": "Snyk API & Web (DAST)", "ai": "AI explanations (4 levels)", "report": "Report",
           "supabase_paste": "Supabase Security Advisor (database)"}
STATUS_EN = {"pending": "queued", "running": "running…", "ok": "done", "skipped": "skipped", "error": "error"}


def status_payload(job: Dict[str, Any]) -> Dict[str, Any]:
    steps = job.get("steps", {})
    order = list(steps.keys())
    done = [k for k in order if steps[k]["status"] in ("ok", "skipped", "error")]
    total = max(1, len(order))
    status = {"queued": "running", "running": "running", "done": "done", "error": "failed"}.get(job.get("status"), "running")
    events = []
    for k in order:
        st = steps[k]
        if st["status"] in ("ok", "running", "error"):
            label = STEP_EN.get(k, st.get("label", k))
            m = re.search(r"(\d+) résultat", st.get("message", ""))
            found = m and int(m.group(1)) > 0
            if st["status"] == "ok" and found:
                text = f"{label}: {m.group(1)} issue(s) found"
                kind = "alert"
            else:
                text = f"{label} — {STATUS_EN.get(st['status'], st['status'])}"
                kind = "info"
            events.append({"text": text, "kind": kind})
    return {
        "status": status,
        "progress": int(100 * len(done) / total),
        "eta_seconds": 0 if status == "done" else max(5, (total - len(done)) * 15),
        "events": events or [{"text": "Starting the audit...", "kind": "info"}],
        "message": job.get("message", ""),
    }
