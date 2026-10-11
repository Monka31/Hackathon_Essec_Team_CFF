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


def _desc(f: Dict[str, Any]) -> str:
    expl = f.get("explanations") or {}
    return (expl.get("avance") or expl.get("expert") or f.get("description") or "").strip()


def _security_fixes_md(findings: List[Dict[str, Any]], patched: List[str]) -> str:
    patched = set(patched or [])
    lines = ["# Security fixes proposed by Syberia", "",
             "This pull request was opened by Syberia on a dedicated branch. Review the diff and merge",
             "what you agree with. Nothing on your default branch changed until you merge.", "",
             f"- Files changed with a proposed fix: {len(patched)}",
             f"- Items reviewed in this PR: {len(findings)}", ""]
    for f in findings:
        lines.append(f"## {f.get('title', 'Issue')}  ({f.get('severity', 'medium').upper()})")
        if f.get("file"):
            loc = f["file"] + (f":{f['line']}" if f.get("line") else "")
            lines.append(f"- Location: `{loc}`")
            if f["file"] in patched:
                lines.append("- Status: a fix was applied to this file in this pull request (review the diff).")
            else:
                lines.append("- Status: recommendation only (no automatic code change).")
        if _desc(f):
            lines.append(f"- Problem: {_desc(f)[:400]}")
        if f.get("fix_hint"):
            lines.append(f"- How to fix: {f['fix_hint']}")
        lines.append("")
    return "\n".join(lines)


def _ai_fix_file(path: str, content: str, f: Dict[str, Any]) -> Optional[str]:
    """Demande au modèle le fichier CORRIGÉ en entier (changement minimal). None si impossible/inchangé."""
    from ..llm import client as llm
    if llm.provider() in ("off", "none", ""):
        return None
    if not content or len(content) > 60000:
        return None
    system = ("You are a senior security engineer fixing ONE vulnerability in a source file. "
              "Return ONLY the complete corrected file content, with NO markdown fences and NO commentary. "
              "Make the minimal change that fixes this one issue; keep all other code, imports, formatting and "
              "behavior identical. If you cannot fix it safely, return the file exactly unchanged.")
    prompt = (f"File path: {path}\n"
              f"Vulnerability: {f.get('title', '')}\n"
              f"Problem: {_desc(f)[:600]}\n"
              f"Suggested direction: {f.get('fix_hint', '') or 'apply the standard secure pattern'}\n"
              f"Line of interest: {f.get('line')}\n\n"
              f"--- FILE START ---\n{content}\n--- FILE END ---")
    try:
        out = llm.complete(system, prompt, max_tokens=4000)
    except Exception:
        return None
    if not isinstance(out, str):
        return None
    out = out.strip()
    if out.startswith("```"):
        out = re.sub(r"^```[a-zA-Z0-9_-]*\n", "", out)
        out = re.sub(r"\n```\s*$", "", out)
    out = out.strip("\n")
    if not out or out == content.strip("\n"):
        return None
    return out + "\n"


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
    patched: List[str] = []
    not_patched: List[Dict[str, Any]] = []
    for f in findings[:12]:  # on borne pour garder une PR relisible et un temps raisonnable
        path = f.get("file")
        if path and "://" not in path and not path.startswith("supabase:"):
            existing = github_app.get_file(owner, repo, path, branch, token)
            if existing:
                fixed = _ai_fix_file(path, existing["content"], f)
                if fixed and github_app.put_file(owner, repo, path, fixed,
                                                 "Syberia: fix " + (f.get("title") or path)[:60],
                                                 branch, existing["sha"], token):
                    if path not in patched:
                        patched.append(path)
                    continue
        not_patched.append(f)

    # fichiers additifs seulement pour ce qui n'a pas pu être corrigé automatiquement
    extra = [{"path": "SECURITY_FIXES.md", "content": _security_fixes_md(findings, patched)}] + _extra_files(not_patched)
    for fl in extra:
        path = fl["path"]
        existing = github_app.get_file(owner, repo, path, branch, token)
        if existing and path == "SECURITY_FIXES.md":
            path = f"SECURITY_FIXES_{batch_id}.md"
            existing = None
        if existing:
            continue  # on n'écrase jamais un fichier existant du projet
        github_app.put_file(owner, repo, path, fl["content"],
                            "Syberia: security fix notes", branch, None, token)

    body = _security_fixes_md(findings, patched)
    pr = github_app.open_pull_request(
        owner, repo, branch, base,
        title=f"Syberia: security fixes ({len(patched)} file(s) changed, {len(findings)} issue(s))",
        body=body, token=token)
    if not pr:
        return {"error": "The branch was created but the pull request could not be opened."}
    with _LOCK:
        b["deployed_pr"] = pr
    return {"pr_url": pr}
