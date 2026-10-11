"""Suivi des failles qui résistent aux corrections, et des risques acceptés.

- record_attempt : chaque tentative de correction (et son résultat) est mémorisée par projet.
- diagnose : pour une faille toujours présente après au moins une tentative, explique POURQUOI
  elle persiste et COMMENT la résoudre (affiché dans le rapport et donné à l'assistant).
- accept / unaccept : l'utilisateur peut marquer une faille comme risque accepté, faux positif
  ou clé révoquée, avec une justification. Elle sort alors du score, mais reste visible.

Stockage : un petit fichier JSON par projet dans DATA_DIR/persistence (pas de secret dedans :
uniquement des identifiants de faille, des statuts et des justifications écrites par l'utilisateur).
"""
from __future__ import annotations

import json
import os
import re
import threading
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

_LOCK = threading.Lock()
ACCEPT_KINDS = {
    "accepted_risk": "Accepted risk",
    "false_positive": "False positive",
    "key_revoked": "Key revoked",
}
# Règles d'analyse de flux (« une entrée utilisateur atteint X ») : le scanner ne voit pas une
# validation écrite à la main, la faille peut donc rester signalée même quand le code est sûr.
_TAINT_HINTS = ("redirect", "ssrf", "request-forgery", "tainted", "injection", "xss", "path-traversal",
                "user-input", "open-redirect", "sqli", "sql")


def _dir() -> Path:
    base = Path(os.getenv("DATA_DIR", Path(__file__).resolve().parents[2] / "data"))
    d = base / "persistence"
    d.mkdir(parents=True, exist_ok=True)
    return d


def _path(project_id: str) -> Path:
    safe = re.sub(r"[^A-Za-z0-9_.-]", "_", project_id or "unknown")[:120]
    return _dir() / f"{safe}.json"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def load(project_id: Optional[str]) -> Dict[str, Any]:
    if not project_id:
        return {"attempts": {}, "accepted": {}}
    try:
        data = json.loads(_path(project_id).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        data = {}
    data.setdefault("attempts", {})
    data.setdefault("accepted", {})
    return data


def _save(project_id: str, data: Dict[str, Any]) -> None:
    p = _path(project_id)
    tmp = p.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=1, ensure_ascii=False), encoding="utf-8")
    tmp.replace(p)


def record_attempt(project_id: Optional[str], finding_id: str, outcome: str, note: str = "",
                   pr_url: Optional[str] = None) -> None:
    """Mémorise une tentative de correction. outcome : voir fixes.OUTCOMES."""
    if not project_id or not finding_id:
        return
    with _LOCK:
        data = load(project_id)
        a = data["attempts"].setdefault(finding_id, {"count": 0, "history": []})
        a["count"] += 1
        a["last_outcome"] = outcome
        a["last_at"] = _now()
        if pr_url:
            a["last_pr"] = pr_url
        a["history"] = (a.get("history") or [])[-4:] + [{"at": a["last_at"], "outcome": outcome, "note": note[:300]}]
        _save(project_id, data)


def accept(project_id: str, finding_id: str, kind: str, reason: str, user: str = "") -> Dict[str, Any]:
    if kind not in ACCEPT_KINDS:
        raise ValueError("unknown kind")
    reason = (reason or "").strip()
    if len(reason) < 10:
        raise ValueError("Please explain in a sentence why this is acceptable (at least 10 characters).")
    entry = {"kind": kind, "label": ACCEPT_KINDS[kind], "reason": reason[:500], "by": user[:80], "at": _now()}
    with _LOCK:
        data = load(project_id)
        data["accepted"][finding_id] = entry
        _save(project_id, data)
    return entry


def unaccept(project_id: str, finding_id: str) -> bool:
    with _LOCK:
        data = load(project_id)
        found = data["accepted"].pop(finding_id, None) is not None
        if found:
            _save(project_id, data)
    return found


def _rule(f: Dict[str, Any]) -> str:
    ev = (f.get("evidence") or [{}])[0] or {}
    return str(f.get("rule_id") or ev.get("rule_id") or "").lower()


def diagnose(f: Dict[str, Any], attempt: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    """Explication d'une faille qui persiste. None si aucune correction n'a encore été tentée."""
    if not attempt or not attempt.get("count"):
        return None
    n = attempt["count"]
    last = attempt.get("last_outcome", "")
    title = (f.get("title") or "").lower()
    cat = f.get("category") or ""
    file = f.get("file") or ""
    rule = _rule(f)
    tries = f"{n} fix attempt{'s' if n > 1 else ''}"

    if cat == "secret" and "git history" in title:
        return {
            "reason": "secret_in_history",
            "title": "The key is gone from the code but still in the git history",
            "explanation": (f"The code was cleaned ({tries}), but git keeps every past version: anyone who clones "
                            "the repository can still read the old value. No code change can remove it."),
            "steps": ["Revoke this key in the provider's dashboard and create a new one.",
                      "Store the new key only in your host's environment variables (never in the code).",
                      "Then mark this issue as 'Key revoked': it will leave the score."],
            "can_accept": "key_revoked",
        }
    if cat == "dependency":
        major = "major" in str(f.get("fix_hint") or "").lower()
        steps = ["Check that the fix pull request was merged into your main branch.",
                 "Make sure package-lock.json was updated in that pull request (run 'npm install' and commit it if not).",
                 "Run the audit again after merging."]
        if major:
            steps.insert(1, "This fix needs a MAJOR version update: test your app locally before merging, "
                            "breaking changes are possible.")
        return {
            "reason": "dependency_not_updated",
            "title": "The vulnerable version is still installed",
            "explanation": (f"After {tries}, the audit still sees the old version. Dependency scanners read "
                            "package-lock.json (the exact installed versions), so the issue stays until the "
                            "updated lockfile is on your main branch."),
            "steps": steps,
            "can_accept": None,
        }
    if cat == "web" or "://" in file:
        return {
            "reason": "needs_redeploy",
            "title": "The live site still runs the old version",
            "explanation": ("This issue is tested on your online app. Merging the fix is not enough: "
                            "the site must be redeployed before the audit can see the change."),
            "steps": ["Merge the fix pull request.", "Redeploy your app (on Vercel, it happens automatically "
                      "after the merge; check the deployment succeeded).", "Run the audit again."],
            "can_accept": None,
        }
    if last == "verified":
        return {
            "reason": "fix_not_merged",
            "title": "A verified fix is waiting in a pull request",
            "explanation": ("The fix was re-scanned and confirmed before the pull request was opened. If the issue "
                            "still shows up, the pull request has most likely not been merged yet."),
            "steps": ["Open the fix pull request on GitHub, review it and merge it.", "Run the audit again."],
            "can_accept": None,
        }
    if any(h in rule or h in title for h in _TAINT_HINTS):
        return {
            "reason": "scanner_cannot_see_validation",
            "title": "The scanner cannot see your validation",
            "explanation": (f"After {tries}, the scanner still flags this line. It detects the pattern 'user input "
                            "reaches a sensitive function', but it cannot read a custom validation function. "
                            "If the input is really checked, the code is safe and the alert is a false positive."),
            "steps": ["Ask the assistant to review the validation on this line.",
                      "If the check is solid (strict allow-list, origin comparison, parameterized query), "
                      "mark the issue as 'Accepted risk' and write why.",
                      "If it is not, fix it by hand following the suggested pattern."],
            "can_accept": "accepted_risk",
        }
    return {
        "reason": "needs_manual_fix",
        "title": "The automatic fix did not work",
        "explanation": (f"After {tries}, no automatic change passed the re-scan, so nothing was proposed. "
                        "This issue needs a developer's decision."),
        "steps": ["Ask the assistant for a step-by-step fix for this exact line.",
                  "Apply it by hand, then run the audit again.",
                  "If you confirm it is not exploitable in your context, mark it as 'Accepted risk' with a reason."],
        "can_accept": "accepted_risk",
    }


def summarize_for_assistant(findings: List[Dict[str, Any]], limit: int = 6) -> List[str]:
    """Lignes de contexte pour l'assistant : les failles persistantes et leur diagnostic."""
    lines = []
    for f in findings:
        p = f.get("persistence")
        if not p:
            continue
        lines.append(f"- [{f.get('severity')}] {f.get('title')} in {f.get('file') or 'n/a'} "
                     f"(id {f.get('id')}): PERSISTENT, reason={p['reason']}: {p['explanation']} "
                     f"Steps: {' / '.join(p['steps'])}")
        if len(lines) >= limit:
            break
    return lines
