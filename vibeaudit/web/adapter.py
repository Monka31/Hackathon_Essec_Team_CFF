"""Traduit le rapport interne vers le format attendu par le nouveau visuel (Syberia).

Contrat (voir prototype.html [CONTRACT]) :
  Finding = { id, project_id, severity, group: code|supply_chain|workflow,
              title, impact, who_can_exploit, rule_id, category, owasp, cwe, layer,
              confidence, file, line, technical_detail, summary,
              code:[{n,text,hit}], proof:{confirmed,text}, fix_status, found_at }
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

LEVEL_MAP = {"debutant": "beginner", "intermediaire": "intermediate", "avance": "advanced", "expert": "expert"}
CONF_MAP = {"haute": "high", "moyenne": "medium", "faible": "low",
            "high": "high", "medium": "medium", "low": "low"}
GROUP = {"dependency": "supply_chain"}  # tout le reste -> "code"
CATEGORY_EN = {"code": "Code issue", "dependency": "Vulnerable component", "secret": "Exposed secret",
               "config": "Security misconfiguration", "web": "Online app"}
LAYER = {"code": "application", "dependency": "supply chain", "secret": "frontend",
         "config": "configuration", "web": "online app"}
OWASP = {"code": "A03", "dependency": "A06", "secret": "A07", "config": "A05", "web": "A05"}

_SNIP = re.compile(r"^(>?)\s*(\d+)\s*\|\s?(.*)$")


def slugify(text: str) -> str:
    s = re.sub(r"[^a-zA-Z0-9]+", "-", (text or "").lower()).strip("-")
    return s[:60] or "project"


def project_id_for(repo_url: Optional[str], app_url: Optional[str]) -> str:
    if repo_url:
        p = urlparse(repo_url)
        parts = [x for x in p.path.split("/") if x]
        if len(parts) >= 2:
            return slugify(parts[0] + "-" + parts[1].replace(".git", ""))
    if app_url:
        return slugify(urlparse(app_url).netloc or app_url)
    return "project"


def project_name_for(repo_url: Optional[str], app_url: Optional[str]) -> str:
    if repo_url:
        parts = [x for x in urlparse(repo_url).path.split("/") if x]
        if len(parts) >= 2:
            return parts[1].replace(".git", "")
    if app_url:
        return urlparse(app_url).netloc or app_url
    return "project"


def _code(snippet: Optional[str]) -> List[Dict[str, Any]]:
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
    return {en: raw[fr] for fr, en in LEVEL_MAP.items() if raw.get(fr)}


def _finding(f: Dict[str, Any], project_id: str, found_at: str) -> Dict[str, Any]:
    cat = f.get("category", "code")
    expl = _explanations(f)
    sources = f.get("sources") or []
    cross = len(sources) > 1
    return {
        "id": f["id"],
        "project_id": project_id,
        "severity": f.get("severity", "medium"),
        "group": GROUP.get(cat, "code"),
        "title": f.get("title", ""),
        "impact": expl.get("beginner") or (f.get("description") or "").split("\n")[0][:300]
                  or "This weakness could put your app or its data at risk.",
        "who_can_exploit": f.get("attack_scenario") or "An attacker able to reach this part of your app.",
        "rule_id": (f.get("evidence") or [{}])[0].get("rule_id") or cat,
        "category": CATEGORY_EN.get(cat, cat),
        "owasp": OWASP.get(cat, ""),
        "cwe": ", ".join(f.get("cwe") or []) or "n/a",
        "layer": LAYER.get(cat, cat),
        "confidence": CONF_MAP.get(f.get("confidence") or "", "medium"),
        "file": f.get("file") or "",
        "line": f.get("line"),
        "technical_detail": f.get("title", ""),
        "summary": expl.get("expert") or (f.get("description") or "")[:1200],
        "code": _code(f.get("snippet")),
        "proof": {
            "confirmed": cross,
            "text": ("confirmed by two independent scanners (" + ", ".join(sources) + ")")
                    if cross else ("detected by " + (sources[0] if sources else "scanner")
                                   + " (static analysis, not an active attack test)"),
        },
        "fix_status": "open",
        "found_at": found_at,
        "explanations": expl,      # bonus : garde les 4 niveaux si le visuel veut les afficher
        "fix_steps": f.get("fix_steps") or [],
    }


def to_prototype(report: Dict[str, Any], project_id: Optional[str] = None,
                 project_name: Optional[str] = None) -> Dict[str, Any]:
    repo_url, app_url = report.get("repo_url"), report.get("app_url")
    pid = project_id or project_id_for(repo_url, app_url)
    pname = project_name or project_name_for(repo_url, app_url)
    findings, ignored = [], []
    for f in report.get("findings", []):
        if f.get("ai_verdict") == "false_positive_suspected":
            ignored.append({
                "rule_id": (f.get("evidence") or [{}])[0].get("rule_id") or f.get("category", ""),
                "location": f"{f.get('file', '')}{':' + str(f['line']) if f.get('line') else ''}",
                "reason": f.get("confidence_reason") or f.get("attack_scenario") or "Likely not exploitable here.",
            })
        else:
            findings.append(_finding(f, pid, "Today"))
    target = app_url or repo_url or report.get("target") or ""
    return {
        "audit_id": report.get("job_id") or "",
        "project_id": pid,
        "project": pname,
        "target": target,
        "type": "deep" if repo_url else "quick",
        "scanned_at": report.get("generated_at"),
        "commit": None,
        "ai": report.get("ai"),
        "ai_summary": report.get("ai_summary"),
        "findings": findings,
        "ignored": ignored,
    }


# ----------------------------------------------------------------- statut live
STEP_EN = {"clone": "Cloning the GitHub repo", "snyk_code": "Snyk Code (code)",
           "snyk_deps": "Snyk Open Source (dependencies)", "semgrep": "Reading your code (Semgrep)",
           "gitleaks": "Looking for exposed secrets", "npm_audit": "Checking your dependencies",
           "supabase": "Supabase Advisor (database)", "web_passive": "Testing your app as an anonymous visitor",
           "snyk_dast": "Snyk API & Web (DAST)", "ai": "Writing your report in plain language",
           "report": "Finishing the report", "supabase_paste": "Checking who can read your database"}
STATUS_EN = {"pending": "queued", "running": "in progress", "ok": "done", "skipped": "skipped", "error": "could not run"}


def status_payload(job: Dict[str, Any]) -> Dict[str, Any]:
    steps = job.get("steps", {})
    order = list(steps.keys())
    done = [k for k in order if steps[k]["status"] in ("ok", "skipped", "error")]
    total = max(1, len(order))
    status = {"queued": "running", "running": "running", "done": "done", "error": "failed"}.get(
        job.get("status"), "running")
    events = []
    for k in order:
        st = steps[k]
        if st["status"] in ("ok", "running", "error"):
            label = STEP_EN.get(k, st.get("label", k))
            m = re.search(r"(\d+) résultat", st.get("message", ""))
            found = m and int(m.group(1)) > 0
            if st["status"] == "ok" and found:
                events.append({"text": f"{label}: {m.group(1)} issue(s) found", "kind": "alert"})
            else:
                events.append({"text": f"{label} — {STATUS_EN.get(st['status'], st['status'])}", "kind": "info"})
    return {
        "status": status,
        "progress": int(100 * len(done) / total),
        "eta_seconds": 0 if status == "done" else max(5, (total - len(done)) * 12),
        "events": events or [{"text": "Starting the audit...", "kind": "info"}],
        "message": job.get("message", ""),
    }
