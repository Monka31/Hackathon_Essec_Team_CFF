#!/usr/bin/env bash
# Construit et (re)lance la plateforme sur le serveur EC2.
# Usage, depuis le dossier du repo sur le serveur :  bash deploy/start.sh
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -f .env ]; then
  echo "Il manque le fichier .env : cp .env.example .env puis remplir SNYK_TOKEN, PROBELY_API_KEY, PLATFORM_ACCESS_CODE..."
  exit 1
fi

git pull --ff-only || true
sudo docker build -t vibeaudit:latest .
sudo docker rm -f vibeaudit 2>/dev/null || true
sudo mkdir -p /opt/vibeaudit-data && sudo chown 10001 /opt/vibeaudit-data
sudo docker run -d --name vibeaudit --restart unless-stopped \
  --env-file .env \
  -e AWS_REGION="${AWS_REGION:-us-west-2}" \
  -v /opt/vibeaudit-data:/data \
  -p 80:8000 \
  --memory 3g --pids-limit 512 \
  vibeaudit:latest

sleep 5
curl -fs http://127.0.0.1/api/health && echo " <- la plateforme répond"
TOKEN=$(curl -s -X PUT "http://169.254.169.254/latest/api/token" -H "X-aws-ec2-metadata-token-ttl-seconds: 60" || true)
IP=$(curl -s -H "X-aws-ec2-metadata-token: $TOKEN" http://169.254.169.254/latest/meta-data/public-ipv4 || true)
echo "Adresse publique : http://${IP:-<IP publique de l'instance>}/"
