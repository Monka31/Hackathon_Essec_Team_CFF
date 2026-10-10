"""Base SQLite de la plateforme : comptes, sessions, historique d'audits.

Principe de sécurité : on ne stocke JAMAIS de jeton GitHub ni de secret ici.
Seulement l'identité publique de l'utilisateur et l'historique de ses audits.
Fichier unique dans DATA_DIR (monté sur un volume Docker pour survivre aux redéploiements).
"""
from __future__ import annotations

import os
import secrets
import sqlite3
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

DATA_DIR = Path(os.getenv("DATA_DIR", Path(__file__).resolve().parents[2] / "data"))
DB_PATH = DATA_DIR / "vibeaudit.db"
SESSION_DAYS = 30

_lock = threading.Lock()


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _conn() -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    c = sqlite3.connect(DB_PATH, timeout=10)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA journal_mode=WAL")
    return c


def init() -> None:
    with _lock, _conn() as c:
        c.executescript(
            """
            CREATE TABLE IF NOT EXISTS users (
              id INTEGER PRIMARY KEY,
              github_id INTEGER UNIQUE,
              login TEXT,
              name TEXT,
              email TEXT,
              avatar_url TEXT,
              method TEXT,                 -- github | email
              onboarded INTEGER DEFAULT 0,
              role TEXT, built_with TEXT, goal TEXT, concerns TEXT,
              created_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS sessions (
              token TEXT PRIMARY KEY,
              user_id INTEGER NOT NULL REFERENCES users(id),
              expires_at TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS audits (
              id TEXT PRIMARY KEY,
              user_id INTEGER REFERENCES users(id),
              project_id TEXT,
              project_name TEXT,
              repo_url TEXT,
              app_url TEXT,
              score INTEGER,
              status TEXT,
              created_at TEXT NOT NULL
            );
            """
        )


# ---------------------------------------------------------------- utilisateurs
def _row_user(r: sqlite3.Row) -> Dict[str, Any]:
    return {
        "id": "u" + str(r["id"]), "db_id": r["id"], "github_id": r["github_id"],
        "login": r["login"], "name": r["name"] or r["login"] or "Founder",
        "email": r["email"], "avatar_url": r["avatar_url"], "method": r["method"],
        "onboarded": bool(r["onboarded"]), "role": r["role"],
    }


def get_or_create_github_user(github_id: int, login: str, name: str, email: Optional[str],
                              avatar_url: Optional[str]) -> Dict[str, Any]:
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM users WHERE github_id=?", (github_id,)).fetchone()
        if r:
            c.execute("UPDATE users SET login=?, name=?, email=COALESCE(?, email), avatar_url=? WHERE github_id=?",
                      (login, name, email, avatar_url, github_id))
            r = c.execute("SELECT * FROM users WHERE github_id=?", (github_id,)).fetchone()
            return _row_user(r)
        cur = c.execute(
            "INSERT INTO users (github_id, login, name, email, avatar_url, method, created_at) "
            "VALUES (?,?,?,?,?, 'github', ?)",
            (github_id, login, name, email, avatar_url, _now()))
        r = c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        return _row_user(r)


def get_or_create_email_user(email: str) -> Dict[str, Any]:
    """Compte léger par email (démo, sans mot de passe)."""
    name = email.split("@")[0] if email else "Founder"
    with _lock, _conn() as c:
        r = c.execute("SELECT * FROM users WHERE email=? AND method='email'", (email,)).fetchone()
        if r:
            return _row_user(r)
        cur = c.execute(
            "INSERT INTO users (login, name, email, method, created_at) VALUES (?,?,?, 'email', ?)",
            (name, name, email, _now()))
        r = c.execute("SELECT * FROM users WHERE id=?", (cur.lastrowid,)).fetchone()
        return _row_user(r)


def get_user(db_id: int) -> Optional[Dict[str, Any]]:
    with _conn() as c:
        r = c.execute("SELECT * FROM users WHERE id=?", (db_id,)).fetchone()
        return _row_user(r) if r else None


def save_onboarding(db_id: int, role: str, built_with: str, goal: str, concerns: List[str]) -> None:
    with _lock, _conn() as c:
        c.execute("UPDATE users SET onboarded=1, role=?, built_with=?, goal=?, concerns=? WHERE id=?",
                  (role, built_with, goal, ",".join(concerns or []), db_id))


# -------------------------------------------------------------------- sessions
def create_session(db_id: int) -> str:
    token = secrets.token_urlsafe(32)
    exp = (datetime.now(timezone.utc) + timedelta(days=SESSION_DAYS)).isoformat(timespec="seconds")
    with _lock, _conn() as c:
        c.execute("INSERT INTO sessions (token, user_id, expires_at) VALUES (?,?,?)", (token, db_id, exp))
    return token


def user_by_session(token: Optional[str]) -> Optional[Dict[str, Any]]:
    if not token:
        return None
    with _conn() as c:
        r = c.execute(
            "SELECT u.* FROM sessions s JOIN users u ON u.id=s.user_id "
            "WHERE s.token=? AND s.expires_at > ?", (token, _now())).fetchone()
        return _row_user(r) if r else None


def delete_session(token: Optional[str]) -> None:
    if not token:
        return
    with _lock, _conn() as c:
        c.execute("DELETE FROM sessions WHERE token=?", (token,))


# ---------------------------------------------------------------------- audits
def save_audit(audit_id: str, user_db_id: Optional[int], project_id: str, project_name: str,
               repo_url: Optional[str], app_url: Optional[str], score: Optional[int], status: str) -> None:
    with _lock, _conn() as c:
        c.execute(
            "INSERT OR REPLACE INTO audits (id, user_id, project_id, project_name, repo_url, app_url, score, status, created_at) "
            "VALUES (?,?,?,?,?,?,?,?, COALESCE((SELECT created_at FROM audits WHERE id=?), ?))",
            (audit_id, user_db_id, project_id, project_name, repo_url, app_url, score, status, audit_id, _now()))


def list_user_audits(user_db_id: int) -> List[Dict[str, Any]]:
    with _conn() as c:
        rows = c.execute("SELECT * FROM audits WHERE user_id=? ORDER BY created_at DESC", (user_db_id,)).fetchall()
        return [dict(r) for r in rows]


def latest_audit_per_project(user_db_id: int) -> List[Dict[str, Any]]:
    """Le dernier audit de chaque projet de l'utilisateur."""
    seen: Dict[str, Dict[str, Any]] = {}
    for a in list_user_audits(user_db_id):
        if a["project_id"] not in seen:
            seen[a["project_id"]] = a
    return list(seen.values())


def audit_owner(audit_id: str) -> Optional[int]:
    with _conn() as c:
        r = c.execute("SELECT user_id FROM audits WHERE id=?", (audit_id,)).fetchone()
        return r["user_id"] if r else None
