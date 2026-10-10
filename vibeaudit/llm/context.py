"""Contexte du projet donné à l'IA pour juger l'exploitabilité réelle (dépendance de dev ? framework ?)."""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, Optional


def project_context(root: Optional[Path], app_url: Optional[str] = None) -> Dict[str, Any]:
    ctx: Dict[str, Any] = {"url_appli": app_url}
    if not root or not root.exists():
        return ctx
    pkg = root / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(encoding="utf-8"))
            deps = sorted((data.get("dependencies") or {}).keys())
            dev = sorted((data.get("devDependencies") or {}).keys())
            ctx["dependances_production"] = deps[:60]
            ctx["dependances_developpement_uniquement"] = dev[:60]
            ctx["scripts"] = sorted((data.get("scripts") or {}).keys())[:20]
            stack = []
            for name, label in (("next", "Next.js"), ("react", "React"), ("@supabase/supabase-js", "Supabase"),
                                ("express", "Express"), ("vue", "Vue"), ("stripe", "Stripe"), ("firebase", "Firebase")):
                if name in deps or name in dev:
                    stack.append(label)
            ctx["stack"] = stack
        except (OSError, json.JSONDecodeError):
            pass
    ctx["fichiers_racine"] = sorted(p.name for p in root.iterdir() if not p.name.startswith(".git"))[:40]
    ctx["a_des_routes_api_serveur"] = any(root.glob("**/app/api/**/route.*")) or any(root.glob("**/pages/api/**"))
    ctx["a_des_migrations_supabase"] = (root / "supabase" / "migrations").exists()
    return ctx
