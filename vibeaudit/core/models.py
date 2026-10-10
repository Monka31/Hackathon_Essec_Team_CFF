"""Format commun d'une faille, quel que soit le scanner d'origine."""
from __future__ import annotations

import hashlib
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, List, Optional

# Gravité sur 4 niveaux (choix C)
SEVERITIES = ["critical", "high", "medium", "low"]
SEVERITY_LABELS_FR = {
    "critical": "Critique",
    "high": "Haute",
    "medium": "Moyenne",
    "low": "Basse",
}

# Catégories de faille
CATEGORIES = {
    "code": "Code",
    "dependency": "Dépendance",
    "secret": "Secret exposé",
    "config": "Configuration",
    "web": "Appli en ligne",
}

# Les 4 niveaux d'explication, remplis par l'IA au module 2
EXPLANATION_LEVELS = ["expert", "avance", "intermediaire", "debutant"]
EXPLANATION_LABELS_FR = {
    "expert": "Dev expert",
    "avance": "Avancé",
    "intermediaire": "Intermédiaire",
    "debutant": "Débutant",
}


def severity_rank(sev: str) -> int:
    """0 = critique (le plus grave), 3 = basse."""
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


@dataclass
class Evidence:
    """Preuve brute : ce qu'un scanner précis a remonté (choix B)."""

    source: str          # "semgrep", "gitleaks", "npm_audit", "snyk_code", "snyk_deps", "supabase"
    rule_id: str
    raw: Dict[str, Any]  # sortie brute du scanner, secrets masqués


@dataclass
class Finding:
    category: str                    # code | dependency | secret | config
    title: str
    severity: str                    # critical | high | medium | low
    file: Optional[str] = None       # chemin relatif au projet, ou "supabase:public.table"
    line: Optional[int] = None
    snippet: Optional[str] = None    # extrait de code, secrets masqués
    description: str = ""            # description brute du scanner
    cwe: List[str] = field(default_factory=list)
    package: Optional[str] = None    # pour les dépendances
    fix_hint: Optional[str] = None   # piste de correction donnée par le scanner
    references: List[str] = field(default_factory=list)
    evidence: List[Evidence] = field(default_factory=list)
    # Rempli au module 2 (IA) : {"expert": "...", "avance": "...", ...}
    explanations: Dict[str, str] = field(default_factory=dict)
    confidence: Optional[str] = None
    attack_scenario: Optional[str] = None

    @property
    def sources(self) -> List[str]:
        return sorted({e.source for e in self.evidence})

    @property
    def merge_key(self) -> tuple:
        """Clé de fusion des doublons (choix E)."""
        if self.category == "dependency":
            return ("dependency", (self.package or self.title).lower())
        if self.line is None:
            # Pas de ligne (configuration, secret dans l'historique) : on distingue par règle
            return (self.category, self.file, self.title)
        return (self.category, self.file, self.line)

    @property
    def id(self) -> str:
        h = hashlib.sha1(repr(self.merge_key).encode()).hexdigest()[:10]
        return f"F-{h}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["id"] = self.id
        d["sources"] = self.sources
        d["severity_label"] = SEVERITY_LABELS_FR.get(self.severity, self.severity)
        d["category_label"] = CATEGORIES.get(self.category, self.category)
        return d


class FindingList(list):
    """Liste de failles + une note pour le rapport (ex : nombre de fichiers analysés)."""

    def __init__(self, items=(), note: str = ""):
        super().__init__(items)
        self.note = note


@dataclass
class ScannerRun:
    """Résultat d'exécution d'un scanner, pour le rapport (choix G)."""

    name: str
    status: str = "ok"            # ok | skipped | error
    message: str = ""
    duration_s: float = 0.0
    findings: List[Finding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "status": self.status,
            "message": self.message,
            "duration_s": round(self.duration_s, 1),
            "raw_count": len(self.findings),
        }
