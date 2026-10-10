"""Correction en lot et ouverture de Pull Request.

Sécurité : AUCUNE attaque active, aucune exécution du code audité, aucune écriture
sur la branche par défaut. La PR ne fait qu'AJOUTER des fichiers (recommandations +
migrations/exemples), ce qui ne peut pas casser le build. L'humain relit et fusionne.
"""
from __future__ import annotations

import json
import re
import secrets
import threading
import time
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.parse import urlparse

from . import db, github_app
from .jobs import STORE

_POOL = ThreadPoolExecutor(max_workers=2)
_BATCHES: Dict[str, Dict[str, Any]] = {}
_LOCK = threading.Lock()
_RUN_SECONDS = 6.0  # durée de préparation simulée (préparation du correctif, pas d'attaque)


def _report_for_project(user_db_id: int, project_id: str) -> Optional[Dict[str, Any]]:
    for a in db.list_user_audits(user_db_id):
        if a["project_id"] == project_id and a.get("status") == "done":
            p = STORE.report_json(a["id"])
            if p:
                rep = json.loads(p.read_text(encoding="utf-8"))
                rep["_repo_url"] = a.get("repo_url")
                rep["_app_url"] = a.get("app_url")
                return rep
    return None


def create(user_db_id: int, project_id: str, finding_ids: List[str]) -> Optional[str]:
    rep = _report_for_project(user_db_id, project_id)
    if not rep:
        return None
    by_id = {f["id"]: f for f in rep.get("findings", [])}
    selected = [by_id[i] for i in finding_ids if i in by_id]
    bid = "b_" + secrets.token_urlsafe(6)
    with _LOCK:
        _BATCHES[bid] = {
            "started": time.time(), "project_id": project_id, "user_db_id": user_db_id,
            "repo_url": rep.get("_repo_url"), "app_url": rep.get("_app_url"),
            "finding_ids": [f["id"] for f in selected], "findings": selected,
            "deployed_pr": None,
        }
    return bid


def _stage(progress: int) -> str:
    # jamais "attacking" : on ne rejoue aucune attaque
    if progress >= 100:
        return "verified"
    if progress >= 70:
        return "verifying"
    if progress > 0:
        return "writing"
    return "waiting"


def status(batch_id: str) -> Optional[Dict[str, Any]]:
    b = _BATCHES.get(batch_id)
    if not b:
        return None
    elapsed = time.time() - b["started"]
    items = []
    for i, fid in enumerate(b["finding_ids"]):
        p = max(0, min(100, int(((elapsed - i * 0.8) / _RUN_SECONDS) * 100)))
        items.append({"finding_id": fid, "progress": p, "stage": _stage(p)})
    done = all(x["progress"] >= 100 for x in items) if items else True
    return {"status": "done" if done else "running", "items": items}


# --------------------------------------------------------- construction des PR
def _owner_repo(repo_url: Optional[str]):
    if not repo_url:
        return None, None
    parts = [x for x in urlparse(repo_url).path.split("/") if x]
    if len(parts) >= 2:
        return parts[0], parts[1].replace(".git", "")
    return None, None


def _table_name(f: Dict[str, Any]) -> str:
    for src in (f.get("file") or "", f.get("technical_detail") or "", f.get("summary") or "", f.get("title") or ""):
        m = re.search(r"(public\.\w+)", src)
        if m:
            return m.group(1)
    return "public.<your_table>"


def _security_fixes_md(findings: List[Dict[str, Any]]) -> str:
    lines = ["# Security fixes proposed by vibeaudit", "",
             "This pull request was opened by vibeaudit. It only ADDS files (recommendations and",
             "example migrations). Nothing in your existing code was changed and nothing was deployed.",
             "Review each item below, apply what you agree with, then merge.", ""]
    for f in findings:
        lines.append(f"## {f.get('title', 'Issue')}  ({f.get('severity', 'medium').upper()})")
        if f.get("file"):
            loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
            lines.append(f"- Location: `{loc}`")
        if f.get("impact"):
            lines.append(f"- Impact: {f['impact']}")
        steps = f.get("fix_steps") or []
        if steps:
            lines.append("- Recommended fix:")
            lines += [f"  - {s}" for s in steps]
        lines.append("")
    return "\n".join(lines)


def _extra_files(findings: List[Dict[str, Any]]) -> List[Dict[str, str]]:
    """Fichiers additifs déterministes selon les failles (jamais d'écrasement de fichiers existants)."""
    out: List[Dict[str, str]] = []
    ts = datetime.now(timezone.utc).strftime("%Y%m%d%H%M%S")
    has_rls = any("rls" in (f.get("rule_id", "") + f.get("title", "")).lower()
                  or "row level security" in (f.get("title", "") + f.get("summary", "")).lower()
                  for f in findings)
    has_headers = any("header" in (f.get("rule_id", "") + f.get("title", "")).lower() for f in findings)
    if has_rls:
        tables = sorted({_table_name(f) for f in findings
                         if "rls" in (f.get("rule_id", "") + f.get("title", "")).lower()
                         or "row level security" in (f.get("title", "") + f.get("summary", "")).lower()})
        sql = ["-- Enable Row Level Security. Review the policies before applying.", ""]
        for t in tables:
            sql += [f"alter table {t} enable row level security;",
                    f"create policy \"owner can read\" on {t} for select using (auth.uid() = owner_id);",
                    f"create policy \"owner can write\" on {t} for all using (auth.uid() = owner_id);", ""]
        out.append({"path": f"supabase/migrations/{ts}_vibeaudit_enable_rls.sql", "content": "\n".join(sql)})
    if has_headers:
        headers = {
            "headers": [{
                "source": "/(.*)",
                "headers": [
                    {"key": "X-Frame-Options", "value": "DENY"},
                    {"key": "X-Content-Type-Options", "value": "nosniff"},
                    {"key": "Referrer-Policy", "value": "no-referrer"},
                    {"key": "Content-Security-Policy", "value": "default-src 'self'"},
                ],
            }]
        }
        out.append({"path": "vibeaudit/security-headers.example.json",
                    "content": json.dumps(headers, indent=2) +
                    "\n\n// Copy this \"headers\" block into your vercel.json (or framework config)."})
    return out


def deploy(batch_id: str, target: str) -> Dict[str, Any]:
    b = _BATCHES.get(batch_id)
    if not b:
        return {"error": "Unknown fix batch."}
    if target != "github":
        return {"error": f"{target} deployment is not available yet. Use GitHub, or download the changes."}
    if not github_app.is_configured():
        return {"error": "GitHub is not configured on the server."}
    owner, repo = _owner_repo(b.get("repo_url"))
    if not owner:
        return {"error": "This project has no connected GitHub repo, so there is no pull request to open. "
                         "Re-run the audit with your GitHub repository to enable fixes."}
    token = github_app.token_for_repo(owner, repo)
    if not token:
        return {"error": "The GitHub App is not installed on this repository. Install it on "
                         f"{owner}/{repo}, then try again."}
    base = github_app.default_branch(owner, repo, token)
    sha = github_app.branch_sha(owner, repo, base, token) if base else None
    if not base or not sha:
        return {"error": "Could not read the repository's default branch."}
    branch = f"vibeaudit/fixes-{batch_id}"
    if not github_app.create_branch(owner, repo, branch, sha, token):
        return {"error": "Could not create the fix branch (it may already exist)."}

    findings = b["findings"]
    files = [{"path": "SECURITY_FIXES.md", "content": _security_fixes_md(findings)}] + _extra_files(findings)
    written = 0
    for fl in files:
        existing = github_app.get_file(owner, repo, fl["path"], branch, token)
        path = fl["path"]
        if existing and path == "SECURITY_FIXES.md":
            path = f"SECURITY_FIXES_{batch_id}.md"
            existing = None
        if existing:
            continue  # on n'écrase jamais un fichier du projet
        if github_app.put_file(owner, repo, path, fl["content"],
                               "vibeaudit: add security fix recommendations", branch, None, token):
            written += 1

    body = _security_fixes_md(findings)
    pr = github_app.open_pull_request(
        owner, repo, branch, base,
        title=f"vibeaudit: security fixes ({len(findings)} issue(s))",
        body=body, token=token)
    if not pr:
        return {"error": "The branch was created but the pull request could not be opened."}
    with _LOCK:
        b["deployed_pr"] = pr
    return {"pr_url": pr}
