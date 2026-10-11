# Hackathon Essec - Team CFF

Projet réalisé lors de **Secure Horizons** (UTOPIA x KRYPTOSPHERE x ESSEC MetaLab), ESSEC Cergy, 10 et 11 octobre 2026.

Track 2 : Defenders Augmented

## Problème

A compléter.

## Solution

**vibeaudit / Syberia** : audit de sécurité des projets vibe-codés. On fournit un dépôt GitHub, un ZIP ou l'URL du site. Les scanners statiques et contrôles passifs remontent des constats; l'IA les explique et peut proposer des edits ciblés dans une Pull Request GitHub. Les edits proposés ne sont pas exécutés ni vérifiés automatiquement; l'humain relit et fusionne.

## Démo

A compléter (scénario d'attaque, puis comment notre solution la bloque).

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

**Plateforme web** (formulaire lien GitHub + URL) :
```
source .venv/bin/activate
python -m vibeaudit serve
```
puis ouvrir http://127.0.0.1:8000

**Ligne de commande** :
```
python -m vibeaudit scan ~/chemin/vers/le/projet --url https://mon-appli.com --out reports/rapport.html
```

Mise en ligne sur AWS : voir `deploy/README-AWS.md`.

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
| Tests passifs (URL) | HTTPS, en-têtes de sécurité, .env ou .git exposés, clés dans le JavaScript | aucun |
| Snyk API & Web (URL) | scan dynamique (DAST) de l'appli en ligne | `PROBELY_API_KEY` + domaine vérifié |

Un scanner absent ou en échec est signalé dans le rapport, sans bloquer les autres.

## Architecture

```
vibeaudit/
  scanners/   un fichier par outil, chacun traduit sa sortie au format commun
  core/       format commun (models), fusion des doublons, score, masquage des secrets
  report/     rapport HTML (template) et JSON
  web/        plateforme : formulaire, suivi des analyses, clonage sécurisé, journal
  llm/        explications des constats et propositions de changements par l'IA
deploy/       Dockerfile et scripts pour EC2
frontend/     interface (Thomas)
demo/         scénario de démo pour le pitch
docs/         schéma d'architecture, slides
```

Règles du score indicatif : 100, moins 25 par faille critique, 10 par haute, 3 par moyenne, 1 par basse, avec un plafond de 40 points par catégorie (plancher 0). Le score résume les constats remontés; ce n'est ni une certification ni une couverture complète de sécurité.
Tout secret est critique. Les secrets sont masqués dans les rapports (4 premiers caractères seulement).

## Sécurité du repo

Les secrets ne sont jamais commités : `.env` est ignoré et chaque commit est scanné par `ggshield` (GitGuardian) via pre-commit.

## Equipe

Team CFF
