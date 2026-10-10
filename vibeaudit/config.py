"""Chargement du .env (les clés ne sont jamais écrites dans le code)."""
from __future__ import annotations

from pathlib import Path

try:
    from dotenv import load_dotenv
except ImportError:  # python-dotenv absent : on lit seulement les variables du Terminal
    load_dotenv = None

TOOL_ROOT = Path(__file__).resolve().parent.parent


def load_env() -> None:
    if load_dotenv is None:
        return
    # Uniquement le .env de l'outil (jamais celui du projet audité). Le Terminal garde la priorité.
    load_dotenv(TOOL_ROOT / ".env", override=False)
