"""Génère le rapport HTML (pour les humains) et JSON (pour l'interface de Thomas)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.models import CATEGORIES, EXPLANATION_LABELS_FR, EXPLANATION_LEVELS, SEVERITY_LABELS_FR

HERE = Path(__file__).resolve().parent


def write_json(report: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")


def write_html(report: Dict[str, Any], path: Path) -> None:
    env = Environment(loader=FileSystemLoader(str(HERE)), autoescape=select_autoescape(["html"]))
    html = env.get_template("template.html").render(
        r=report,
        sev_labels=SEVERITY_LABELS_FR,
        cat_labels=CATEGORIES,
        levels=EXPLANATION_LEVELS,
        level_labels=EXPLANATION_LABELS_FR,
    )
    path.write_text(html, encoding="utf-8")
