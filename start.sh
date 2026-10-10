#!/usr/bin/env bash
# Point d'entrée unique pour la démo : lance la plateforme sur http://127.0.0.1:8000
set -e
cd "$(dirname "$0")"
echo "Démarrage du projet Team CFF..."
if [ ! -d .venv ]; then
  python3 -m venv .venv
  .venv/bin/pip install -q -r requirements.txt
fi
source .venv/bin/activate
python -m vibeaudit serve
