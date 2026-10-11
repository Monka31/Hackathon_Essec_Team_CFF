"""GitHub App : identité de l'utilisateur (OAuth) + accès aux repos (jeton d'installation).

Aucune valeur sensible n'est écrite dans le code : tout vient des variables d'environnement.
Le jeton d'installation est court (1 h) et redemandé à la volée, jamais stocké.
"""
from __future__ import annotations

import base64
import os
import time
from typing import Any, Dict, List, Optional, Tuple

import jwt
import requests

API = "https://api.github.com"
UA = "vibeaudit"
_TIMEOUT = 20


def _private_key() -> Optional[str]:
    b64 = os.getenv("GITHUB_APP_PRIVATE_KEY_B64")
    if b64:
        try:
            return base64.b64decode(b64).decode("utf-8")
        except Exception:
            return None
    path = os.getenv("GITHUB_APP_PRIVATE_KEY_PATH")
    if path and os.path.exists(path):
        return open(path, "r", encoding="utf-8").read()
    return None


def app_id() -> Optional[str]:
    return os.getenv("GITHUB_APP_ID")


def client_id() -> Optional[str]:
    return os.getenv("GITHUB_APP_CLIENT_ID")


def base_url() -> str:
    return os.getenv("APP_BASE_URL", "http://localhost:8000").rstrip("/")


def is_configured() -> bool:
    return bool(app_id() and client_id() and os.getenv("GITHUB_APP_CLIENT_SECRET") and _private_key())


# --------------------------------------------------------- jeton d'installation
def app_jwt() -> str:
    key = _private_key()
    now = int(time.time())
    payload = {"iat": now - 30, "exp": now + 9 * 60, "iss": app_id()}
    return jwt.encode(payload, key, algorithm="RS256")


def _app_headers() -> Dict[str, str]:
    return {"Authorization": f"Bearer {app_jwt()}", "Accept": "application/vnd.github+json", "User-Agent": UA}


def installation_id_for_repo(owner: str, repo: str) -> Optional[int]:
    r = requests.get(f"{API}/repos/{owner}/{repo}/installation", headers=_app_headers(), timeout=_TIMEOUT)
    if r.status_code == 200:
        return r.json().get("id")
    return None


def installation_token(installation_id: int) -> Optional[str]:
    r = requests.post(f"{API}/app/installations/{installation_id}/access_tokens",
                      headers=_app_headers(), timeout=_TIMEOUT)
    if r.status_code in (200, 201):
        return r.json().get("token")
    return None


def token_for_repo(owner: str, repo: str) -> Optional[str]:
    """Jeton court permettant de cloner le repo et d'ouvrir une PR. None si l'App n'y est pas installée."""
    inst = installation_id_for_repo(owner, repo)
    if not inst:
        return None
    return installation_token(inst)


# ------------------------------------------------------------------ OAuth login
def oauth_authorize_url(state: str) -> str:
    redirect = base_url() + "/api/auth/github/callback"
    return (f"https://github.com/login/oauth/authorize?client_id={client_id()}"
            f"&redirect_uri={requests.utils.quote(redirect, safe='')}&state={state}")


def exchange_code(code: str) -> Optional[str]:
    r = requests.post("https://github.com/login/oauth/access_token",
                      headers={"Accept": "application/json", "User-Agent": UA},
                      data={"client_id": client_id(), "client_secret": os.getenv("GITHUB_APP_CLIENT_SECRET"),
                            "code": code, "redirect_uri": base_url() + "/api/auth/github/callback"},
                      timeout=_TIMEOUT)
    if r.status_code == 200:
        return r.json().get("access_token")
    return None


def get_authenticated_user(user_token: str) -> Optional[Dict[str, Any]]:
    h = {"Authorization": f"Bearer {user_token}", "Accept": "application/vnd.github+json", "User-Agent": UA}
    r = requests.get(f"{API}/user", headers=h, timeout=_TIMEOUT)
    if r.status_code != 200:
        return None
    u = r.json()
    email = u.get("email")
    if not email:
        er = requests.get(f"{API}/user/emails", headers=h, timeout=_TIMEOUT)
        if er.status_code == 200:
            primary = next((e for e in er.json() if e.get("primary")), None)
            email = (primary or {}).get("email")
    return {"github_id": u.get("id"), "login": u.get("login"),
            "name": u.get("name") or u.get("login"), "email": email, "avatar_url": u.get("avatar_url")}


def list_installed_repos(user_token: str) -> List[Dict[str, Any]]:
    """Repos sur lesquels l'utilisateur a installé l'App (pour l'audit profond via provider github)."""
    h = {"Authorization": f"Bearer {user_token}", "Accept": "application/vnd.github+json", "User-Agent": UA}
    out: List[Dict[str, Any]] = []
    r = requests.get(f"{API}/user/installations", headers=h, timeout=_TIMEOUT)
    if r.status_code != 200:
        return out
    for inst in r.json().get("installations", []):
        rr = requests.get(f"{API}/user/installations/{inst['id']}/repositories",
                          headers=h, timeout=_TIMEOUT)
        if rr.status_code == 200:
            for repo in rr.json().get("repositories", []):
                out.append({"full_name": repo["full_name"], "private": repo["private"],
                            "html_url": repo["html_url"]})
    return out


# ------------------------------------------------------- API repo (pour les PR)
def _repo_headers(token: str) -> Dict[str, str]:
    return {"Authorization": f"Bearer {token}", "Accept": "application/vnd.github+json", "User-Agent": UA}


def default_branch(owner: str, repo: str, token: str) -> Optional[str]:
    r = requests.get(f"{API}/repos/{owner}/{repo}", headers=_repo_headers(token), timeout=_TIMEOUT)
    return r.json().get("default_branch") if r.status_code == 200 else None


def branch_sha(owner: str, repo: str, branch: str, token: str) -> Optional[str]:
    r = requests.get(f"{API}/repos/{owner}/{repo}/git/ref/heads/{branch}",
                     headers=_repo_headers(token), timeout=_TIMEOUT)
    return r.json().get("object", {}).get("sha") if r.status_code == 200 else None


def create_branch(owner: str, repo: str, new_branch: str, from_sha: str, token: str) -> bool:
    r = requests.post(f"{API}/repos/{owner}/{repo}/git/refs", headers=_repo_headers(token),
                      json={"ref": f"refs/heads/{new_branch}", "sha": from_sha}, timeout=_TIMEOUT)
    return r.status_code in (200, 201)


def get_file(owner: str, repo: str, path: str, ref: str, token: str) -> Optional[Dict[str, Any]]:
    r = requests.get(f"{API}/repos/{owner}/{repo}/contents/{path}", headers=_repo_headers(token),
                     params={"ref": ref}, timeout=_TIMEOUT)
    if r.status_code == 200:
        j = r.json()
        if isinstance(j, dict) and j.get("content"):
            content = base64.b64decode(j["content"]).decode("utf-8", errors="replace")
            return {"sha": j["sha"], "content": content}
    # Fichier > 1 Mo : l'API contents renvoie 403/vide. On récupère le sha via le listing du dossier,
    # puis le contenu via l'API blobs (jusqu'à 100 Mo). Indispensable pour les gros package-lock.json.
    return _get_large_file(owner, repo, path, ref, token)


def _get_large_file(owner: str, repo: str, path: str, ref: str, token: str) -> Optional[Dict[str, Any]]:
    folder, name = (path.rsplit("/", 1) + [""])[:2] if "/" in path else ("", path)
    lr = requests.get(f"{API}/repos/{owner}/{repo}/contents/{folder}", headers=_repo_headers(token),
                      params={"ref": ref}, timeout=_TIMEOUT)
    if lr.status_code != 200 or not isinstance(lr.json(), list):
        return None
    entry = next((e for e in lr.json() if e.get("path") == path or e.get("name") == name), None)
    if not entry or not entry.get("sha"):
        return None
    br = requests.get(f"{API}/repos/{owner}/{repo}/git/blobs/{entry['sha']}", headers=_repo_headers(token),
                      timeout=_TIMEOUT)
    if br.status_code != 200:
        return None
    bj = br.json()
    content = base64.b64decode(bj["content"]).decode("utf-8", errors="replace") if bj.get("content") else ""
    return {"sha": entry["sha"], "content": content}


def put_file(owner: str, repo: str, path: str, new_content: str, message: str, branch: str,
             sha: Optional[str], token: str) -> bool:
    body = {"message": message, "branch": branch,
            "content": base64.b64encode(new_content.encode("utf-8")).decode("ascii")}
    if sha:
        body["sha"] = sha
    r = requests.put(f"{API}/repos/{owner}/{repo}/contents/{path}", headers=_repo_headers(token),
                     json=body, timeout=_TIMEOUT)
    return r.status_code in (200, 201)


def list_tree(owner: str, repo: str, ref: str, token: str, limit: int = 400) -> List[str]:
    """Liste (plate) des chemins de fichiers du repo, pour donner le contexte projet à l'agent.
    Bornée pour rester lisible ; ignore les dossiers lourds (node_modules, .git, build...)."""
    sha = branch_sha(owner, repo, ref, token)
    if not sha:
        return []
    r = requests.get(f"{API}/repos/{owner}/{repo}/git/trees/{sha}", headers=_repo_headers(token),
                     params={"recursive": "1"}, timeout=_TIMEOUT)
    if r.status_code != 200:
        return []
    skip = ("node_modules/", ".git/", "dist/", "build/", ".next/", "vendor/", ".venv/",
            "venv/", "__pycache__/", ".cache/", "coverage/", "out/")
    out: List[str] = []
    for node in r.json().get("tree", []):
        if node.get("type") != "blob":
            continue
        path = node.get("path", "")
        if any(s in ("/" + path + "/") or path.startswith(s) for s in skip):
            continue
        out.append(path)
        if len(out) >= limit:
            break
    return out


def app_slug() -> Optional[str]:
    r = requests.get(f"{API}/app", headers=_app_headers(), timeout=_TIMEOUT)
    return r.json().get("slug") if r.status_code == 200 else None


def install_url() -> str:
    slug = app_slug()
    return f"https://github.com/apps/{slug}/installations/new" if slug else "https://github.com/settings/installations"


def installations_for_account(login: Optional[str]) -> List[int]:
    r = requests.get(f"{API}/app/installations", headers=_app_headers(), timeout=_TIMEOUT,
                     params={"per_page": 100})
    out: List[int] = []
    if r.status_code == 200:
        for inst in r.json():
            acct = (inst.get("account") or {}).get("login")
            if not login or (acct and acct.lower() == login.lower()):
                out.append(inst["id"])
    return out


def _repos_for_installation(inst_id: int) -> List[Dict[str, Any]]:
    tok = installation_token(inst_id)
    if not tok:
        return []
    r = requests.get(f"{API}/installation/repositories", headers=_repo_headers(tok),
                     timeout=_TIMEOUT, params={"per_page": 100})
    if r.status_code == 200:
        return [{"full_name": x["full_name"], "private": x["private"], "html_url": x["html_url"]}
                for x in r.json().get("repositories", [])]
    return []


def repos_for_account(login: Optional[str]) -> List[Dict[str, Any]]:
    seen: Dict[str, Dict[str, Any]] = {}
    for inst in installations_for_account(login):
        for repo in _repos_for_installation(inst):
            seen[repo["full_name"]] = repo
    return list(seen.values())


def open_pull_request(owner: str, repo: str, head: str, base: str, title: str, body: str,
                      token: str) -> Optional[str]:
    r = requests.post(f"{API}/repos/{owner}/{repo}/pulls", headers=_repo_headers(token),
                      json={"title": title, "head": head, "base": base, "body": body}, timeout=_TIMEOUT)
    if r.status_code in (200, 201):
        return r.json().get("html_url")
    return None
