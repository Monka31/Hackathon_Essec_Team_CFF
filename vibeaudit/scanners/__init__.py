"""Registre des scanners. Pour en ajouter un : une fonction scan(root) -> List[Finding]."""
from . import gitleaks, npm_audit, semgrep, snyk, supabase

SCANNERS = {
    "semgrep": semgrep.scan,
    "snyk_code": snyk.scan_code,
    "snyk_deps": snyk.scan_deps,
    "gitleaks": gitleaks.scan,
    "npm_audit": npm_audit.scan,
    "supabase": supabase.scan,
}

LABELS = {
    "semgrep": "Semgrep (code)",
    "snyk_code": "Snyk Code (code)",
    "snyk_deps": "Snyk Open Source (dépendances)",
    "gitleaks": "Gitleaks (secrets)",
    "npm_audit": "npm audit (dépendances)",
    "supabase": "Supabase Advisor (base de données)",
}
