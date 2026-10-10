"""Génère le rapport HTML (pour les humains) et JSON (pour l'interface de Thomas)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jinja2 import Environment, FileSystemLoader, select_autoescape

from ..core.models import CATEGORIES, EXPLANATION_LABELS_FR, EXPLANATION_LEVELS, SEVERITY_LABELS_FR

HERE = Path(__file__).resolve().parent


def _public(report: Dict[str, Any]) -> Dict[str, Any]:
    return {k: v for k, v in report.items() if not k.startswith("_")}


def write_json(report: Dict[str, Any], path: Path) -> None:
    path.write_text(json.dumps(_public(report), ensure_ascii=False, indent=2), encoding="utf-8")


_ENV = Environment(loader=FileSystemLoader(str(HERE)), autoescape=select_autoescape(["html"]))


def render_html(report: Dict[str, Any]) -> str:
    return _ENV.get_template("template.html").render(
        r=report,
        sev_labels=SEVERITY_LABELS_FR,
        cat_labels=CATEGORIES,
        levels=EXPLANATION_LEVELS,
        level_labels=EXPLANATION_LABELS_FR,
    )


def write_html(report: Dict[str, Any], path: Path) -> None:
    path.write_text(render_html(_public(report)), encoding="utf-8")
