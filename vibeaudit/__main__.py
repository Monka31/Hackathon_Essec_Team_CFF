"""Ligne de commande : python -m vibeaudit scan <dossier> [--out rapport.html]"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .config import load_env
from .scanners import SCANNERS

COLORS = {"critical": "\033[91m", "high": "\033[33m", "medium": "\033[93m", "low": "\033[94m"}
RESET = "\033[0m"


def _csv(value: str):
    return {x.strip() for x in value.split(",") if x.strip()} if value else None


def cmd_scan(args: argparse.Namespace) -> int:
    from .core.runner import audit
    from .report.render import write_html, write_json

    target = Path(args.path).expanduser()
    if not target.is_dir():
        print(f"Dossier introuvable : {target}", file=sys.stderr)
        return 2
    only, skip = _csv(args.only), _csv(args.skip)
    for n in (only or set()) | (skip or set()):
        if n not in SCANNERS:
            print(f"Scanner inconnu : {n}. Disponibles : {', '.join(SCANNERS)}", file=sys.stderr)
            return 2

    print(f"Audit de {target.resolve()} ...")
    report = audit(target, only=only, skip=skip)

    for s in report["scanners"]:
        mark = {"ok": "OK ", "skipped": "-- ", "error": "ERR"}[s["status"]]
        print(f"  [{mark}] {s['label']:<38} {s['message']} ({s['duration_s']} s)")

    print()
    for f in report["findings"][:15]:
        loc = f"{f['file']}:{f['line']}" if f.get("line") else (f.get("file") or "")
        print(f"  {COLORS.get(f['severity'], '')}{f['severity_label']:<9}{RESET} {f['title'][:70]}  ({loc})")
    if report["total"] > 15:
        print(f"  ... et {report['total'] - 15} autre(s) dans le rapport")

    c = report["counts"]
    print(
        f"\nScore : {report['score']}/100 (note {report['grade']})  |  "
        f"{c['critical']} critique(s), {c['high']} haute(s), {c['medium']} moyenne(s), {c['low']} basse(s)"
    )

    out_html = Path(args.out)
    out_json = Path(args.json) if args.json else out_html.with_suffix(".json")
    out_html.parent.mkdir(parents=True, exist_ok=True)
    out_json.parent.mkdir(parents=True, exist_ok=True)
    write_html(report, out_html)
    write_json(report, out_json)
    print(f"Rapport HTML : {out_html.resolve()}\nRapport JSON : {out_json.resolve()}")
    return 0


def main() -> int:
    load_env()
    p = argparse.ArgumentParser(prog="vibeaudit", description="Audit de sécurité d'un projet vibe-codé")
    sub = p.add_subparsers(dest="cmd", required=True)
    s = sub.add_parser("scan", help="scanner un dossier de projet")
    s.add_argument("path", help="dossier du projet à auditer")
    s.add_argument("--out", default="rapport.html", help="fichier HTML de sortie (défaut : rapport.html)")
    s.add_argument("--json", default=None, help="fichier JSON de sortie (défaut : même nom que --out)")
    s.add_argument("--only", default="", help=f"scanners à lancer, séparés par des virgules ({','.join(SCANNERS)})")
    s.add_argument("--skip", default="", help="scanners à ignorer, ex : snyk_code,snyk_deps")
    s.set_defaults(func=cmd_scan)
    args = p.parse_args()
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main())
