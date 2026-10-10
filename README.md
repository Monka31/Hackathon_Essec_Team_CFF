# Hackathon Essec - Team CFF

Projet réalisé lors de **Secure Horizons** (UTOPIA x KRYPTOSPHERE x ESSEC MetaLab), ESSEC Cergy, 10 et 11 octobre 2026.

Track 2 : Defenders Augmented

## Problème

A compléter.

## Solution

A compléter.

## Démo

A compléter (scénario d'attaque, puis comment notre solution la bloque).

## Lancer le projet

```bash
cp .env.example .env   # puis renseigner les clés
./start.sh
```

## Structure

```
backend/    API et logique de détection
frontend/   dashboard de démo
demo/       scénario d'attaque scripté pour le pitch
docs/       schéma d'architecture, slides
```

## Sécurité du repo

Les secrets ne sont jamais commités : `.env` est ignoré et chaque commit est scanné par `ggshield` (GitGuardian) via pre-commit.

## Equipe

Team CFF
