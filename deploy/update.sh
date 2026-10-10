#!/usr/bin/env bash
# Met à jour la plateforme sur le serveur EC2 avec la dernière version du code.
# À lancer SUR le serveur (EC2 Instance Connect) :
#   sudo git -C /opt/app/repo pull
#   sudo bash /opt/app/repo/deploy/update.sh
set -e
cd /opt/app/repo
git pull --ff-only || true
docker build -t vibeaudit:latest .
docker rm -f vibeaudit 2>/dev/null || true
docker run -d --name vibeaudit --restart unless-stopped --env-file .env \
  -p 80:8000 --memory 3g --pids-limit 512 vibeaudit:latest
sleep 5
curl -fs http://127.0.0.1/api/health && echo " <- la plateforme répond (mise à jour OK)"
