# vibeaudit (nom provisoire)

Audit de sécurité des projets vibe-codés : on scanne le code, les dépendances, les secrets et la configuration de la base, puis on produit un rapport avec un score sur 100.

Projet de la Team CFF, hackathon Secure Horizons (ESSEC, octobre 2026), Track 2.

## Installation (une fois)

```
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # puis remplir les valeurs utiles

brew install semgrep gitleaks
npm install -g snyk && snyk auth
```

## Utilisation

```
source .venv/bin/activate
python -m vibeaudit scan ~/chemin/vers/le/projet --out reports/rapport.html
```

Options :
- `--skip snyk_code,snyk_deps` pour économiser le quota Snyk
- `--only gitleaks,npm_audit` pour un scan rapide
- `--json chemin.json` pour choisir où écrire le JSON (par défaut, à côté du HTML)

Le JSON a la même structure que le HTML : c'est lui que l'interface lit.

## Ce qui est scanné

| Scanner | Ce qu'il trouve | Prérequis |
|---|---|---|
| Semgrep | failles dans le code (injections, eval...) | `brew install semgrep` |
| Snyk Code | failles dans le code | `snyk auth` |
| Snyk Open Source | dépendances vulnérables | `snyk auth` |
| Gitleaks | secrets dans le code et l'historique git | `brew install gitleaks` |
| npm audit | dépendances vulnérables | `package-lock.json` |
| Supabase Advisor | tables sans RLS, fonctions exposées... | token + ref dans `.env` |

Un scanner absent ou en échec est signalé dans le rapport, sans bloquer les autres.

## Architecture

```
vibeaudit/
  scanners/   un fichier par outil, chacun traduit sa sortie au format commun
  core/       format commun (models), fusion des doublons, score, masquage des secrets
  report/     rapport HTML (template) et JSON
  llm/        module 2 : explications en 4 niveaux par l'IA (à venir)
```

Règles du score : 100, moins 25 par faille critique, 10 par haute, 3 par moyenne, 1 par basse (plancher 0).
Tout secret est critique. Les secrets sont masqués dans les rapports (4 premiers caractères seulement).
