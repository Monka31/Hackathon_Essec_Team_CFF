"""
vibeaudit — Brique B : base de données SQLite.

Module autonome, sans ORM (sqlite3 de la librairie standard).
Contrat d'intégration (cf. cahier des charges §8) :
    get_or_create_user, create_session, get_user_by_session,
    save_audit, list_user_audits
+ quelques helpers : init_db, delete_session, update_audit_status,
  get_audit, purge_expired_sessions.

Règles de sécurité appliquées :
- Aucun jeton GitHub ni secret n'est stocké en base.
- Le token de session n'est stocké que sous forme de hash SHA-256 :
  une fuite du fichier .db ne permet pas de réutiliser les sessions.
- Toutes les requêtes sont paramétrées (pas de concaténation SQL).
"""

from __future__ import annotations

import hashlib
import os
import secrets
import sqlite3
from contextlib import contextmanager
from datetime import datetime, timedelta, timezone
from typing import Iterator, Optional

DB_PATH = os.getenv("VIBEAUDIT_DB_PATH", "/data/vibeaudit.db")
SESSION_TTL_HOURS = int(os.getenv("SESSION_TTL_HOURS", "24"))

AUDIT_STATUSES = {"queued", "running", "done", "error"}

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
  id          INTEGER PRIMARY KEY,
  github_id   INTEGER UNIQUE NOT NULL,
  login       TEXT NOT NULL,
  name        TEXT,
  avatar_url  TEXT,
  created_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token       TEXT PRIMARY KEY,           -- hash SHA-256 du token du cookie
  user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  expires_at  TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS audits (
  id          TEXT PRIMARY KEY,           -- audit_id déjà généré par l'API
  user_id     INTEGER REFERENCES users(id) ON DELETE SET NULL,  -- nullable : audit anonyme
  repo_url    TEXT,
  app_url     TEXT,
  score       INTEGER,
  status      TEXT NOT NULL DEFAULT 'queued'
              CHECK (status IN ('queued','running','done','error')),
  created_at  TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_sessions_user    ON sessions(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_expires ON sessions(expires_at);
CREATE INDEX IF NOT EXISTS idx_audits_user_date ON audits(user_id, created_at DESC);
"""


# ---------------------------------------------------------------- utilitaires

def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(dt: datetime) -> str:
    return dt.isoformat(timespec="seconds")


def _hash_token(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


@contextmanager
def get_conn() -> Iterator[sqlite3.Connection]:
    """Une connexion par appel : simple et sûr avec les threads de FastAPI."""
    conn = sqlite3.connect(DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def init_db() -> None:
    """Crée le dossier, les tables et les index. Idempotent : à appeler au démarrage."""
    folder = os.path.dirname(DB_PATH)
    if folder:
        os.makedirs(folder, exist_ok=True)
    with get_conn() as conn:
        conn.execute("PRAGMA journal_mode = WAL")  # lectures pendant les écritures
        conn.executescript(SCHEMA)


# ---------------------------------------------------------------------- users

def get_or_create_user(github_id: int, login: str,
                       name: Optional[str] = None,
                       avatar_url: Optional[str] = None) -> dict:
    """Crée l'utilisateur, ou met à jour login/nom/avatar s'il existe déjà."""
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO users (github_id, login, name, avatar_url, created_at)
            VALUES (?, ?, ?, ?, ?)
            ON CONFLICT(github_id) DO UPDATE SET
              login = excluded.login,
              name = excluded.name,
              avatar_url = excluded.avatar_url
            """,
            (github_id, login, name, avatar_url, _iso(_now())),
        )
        row = conn.execute(
            "SELECT * FROM users WHERE github_id = ?", (github_id,)
        ).fetchone()
    return dict(row)


# ------------------------------------------------------------------- sessions

def create_session(user_id: int, ttl_hours: int = SESSION_TTL_HOURS) -> str:
    """Renvoie le token en clair (à mettre dans le cookie httpOnly).
    Seul son hash est enregistré en base."""
    token = secrets.token_urlsafe(32)
    expires = _now() + timedelta(hours=ttl_hours)
    with get_conn() as conn:
        conn.execute(
            "INSERT INTO sessions (token, user_id, expires_at) VALUES (?, ?, ?)",
            (_hash_token(token), user_id, _iso(expires)),
        )
    return token


def get_user_by_session(token: Optional[str]) -> Optional[dict]:
    """Utilisateur associé au cookie, ou None si absent / inconnu / expiré."""
    if not token:
        return None
    hashed = _hash_token(token)
    with get_conn() as conn:
        row = conn.execute(
            """
            SELECT u.*, s.expires_at AS session_expires_at
            FROM sessions s JOIN users u ON u.id = s.user_id
            WHERE s.token = ?
            """,
            (hashed,),
        ).fetchone()
        if row is None:
            return None
        if row["session_expires_at"] <= _iso(_now()):
            conn.execute("DELETE FROM sessions WHERE token = ?", (hashed,))
            return None
    user = dict(row)
    user.pop("session_expires_at", None)
    return user


def delete_session(token: Optional[str]) -> None:
    """Pour POST /api/auth/logout."""
    if not token:
        return
    with get_conn() as conn:
        conn.execute("DELETE FROM sessions WHERE token = ?", (_hash_token(token),))


def purge_expired_sessions() -> int:
    """Ménage optionnel (au démarrage par exemple). Renvoie le nombre supprimé."""
    with get_conn() as conn:
        cur = conn.execute("DELETE FROM sessions WHERE expires_at <= ?", (_iso(_now()),))
        return cur.rowcount


# --------------------------------------------------------------------- audits

def save_audit(audit_id: str, user_id: Optional[int] = None,
               repo_url: Optional[str] = None, app_url: Optional[str] = None,
               score: Optional[int] = None, status: str = "queued") -> dict:
    """Crée l'audit, ou le met à jour s'il existe (queued -> running -> done).
    Les champs passés à None ne remplacent pas une valeur déjà connue."""
    if status not in AUDIT_STATUSES:
        raise ValueError(f"status invalide : {status}")
    with get_conn() as conn:
        conn.execute(
            """
            INSERT INTO audits (id, user_id, repo_url, app_url, score, status, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
              user_id  = COALESCE(excluded.user_id,  audits.user_id),
              repo_url = COALESCE(excluded.repo_url, audits.repo_url),
              app_url  = COALESCE(excluded.app_url,  audits.app_url),
              score    = COALESCE(excluded.score,    audits.score),
              status   = excluded.status
            """,
            (audit_id, user_id, repo_url, app_url, score, status, _iso(_now())),
        )
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    return dict(row)


def update_audit_status(audit_id: str, status: str,
                        score: Optional[int] = None) -> None:
    if status not in AUDIT_STATUSES:
        raise ValueError(f"status invalide : {status}")
    with get_conn() as conn:
        conn.execute(
            "UPDATE audits SET status = ?, score = COALESCE(?, score) WHERE id = ?",
            (status, score, audit_id),
        )


def get_audit(audit_id: str) -> Optional[dict]:
    with get_conn() as conn:
        row = conn.execute("SELECT * FROM audits WHERE id = ?", (audit_id,)).fetchone()
    return dict(row) if row else None


def list_user_audits(user_id: int, limit: int = 50) -> list[dict]:
    """Historique pour GET /api/me/audits, du plus récent au plus ancien."""
    with get_conn() as conn:
        rows = conn.execute(
            """
            SELECT id, repo_url, app_url, score, status, created_at
            FROM audits WHERE user_id = ?
            ORDER BY created_at DESC LIMIT ?
            """,
            (user_id, limit),
        ).fetchall()
    return [dict(r) for r in rows]
