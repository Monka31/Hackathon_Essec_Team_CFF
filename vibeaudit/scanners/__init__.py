"""Registre des scanners.

- SCANNERS : analysent le code d'un dossier (repo cloné). Signature : scan(root: Path) -> List[Finding]
- URL_SCANNERS : analysent l'appli en ligne. Signature : scan_url(url: str) -> List[Finding]
"""
from . import gitleaks, npm_audit, semgrep, snyk, snyk_dast, supabase, web_passive

SCANNERS = {
    "snyk_code": snyk.scan_code,
    "snyk_deps": snyk.scan_deps,
    "semgrep": semgrep.scan,
    "gitleaks": gitleaks.scan,
    "npm_audit": npm_audit.scan,
    "supabase": supabase.scan,
}

URL_SCANNERS = {
    "web_passive": web_passive.scan_url,
    "snyk_dast": snyk_dast.scan_url,
}

ALL = list(SCANNERS) + list(URL_SCANNERS)

LABELS = {
    "snyk_code": "Snyk Code (code)",
    "snyk_deps": "Snyk Open Source (dépendances)",
    "semgrep": "Semgrep (code)",
    "gitleaks": "Gitleaks (secrets)",
    "npm_audit": "npm audit (dépendances)",
    "supabase": "Supabase Advisor (base de données)",
    "web_passive": "Tests passifs (appli en ligne)",
    "snyk_dast": "Snyk API & Web (DAST, appli en ligne)",
    "clone": "Clonage du repo",
    "ai": "Explications IA",
    "report": "Rapport",
}
