#!/usr/bin/env bash
# =============================================================================
# Déploiement de vibeaudit sur AWS (EC2 + Docker), piloté en ligne de commande.
# À lancer DANS TON terminal (celui qui atteint AWS, en 4G), pas depuis Claude.
#
# Avant de lancer, dans le MÊME terminal :
#   1) colle les 3 lignes "export AWS_..." de Workshop Studio (identifiants temporaires)
#   2) exporte ton token GitHub lecture seule :   export GH_TOKEN=github_pat_xxx
#   3) lance :   bash deploy/aws-launch.sh
#
# Le script ne stocke aucun secret sur disque. Le token GitHub ne sert qu'au
# clonage sur le serveur. Pense à le révoquer après la démo.
# =============================================================================
set -euo pipefail

REGION="${AWS_REGION:-us-west-2}"
export AWS_DEFAULT_REGION="$REGION"
GH_REPO="${GH_REPO:-Monka31/Hackathon_Essec_Team_CFF}"
NAME="vibeaudit"
TYPE="${INSTANCE_TYPE:-t3.large}"

say(){ printf "\n\033[1m==> %s\033[0m\n" "$*"; }
die(){ printf "\n\033[91mErreur : %s\033[0m\n" "$*" >&2; exit 1; }

command -v aws >/dev/null || die "aws CLI introuvable. Installe-le : brew install awscli"
[ -n "${GH_TOKEN:-}" ] || die "Exporte ton token GitHub d'abord :  export GH_TOKEN=github_pat_xxx"

say "Vérification des identifiants AWS"
ACCOUNT=$(aws sts get-caller-identity --query Account --output text) \
  || die "Identifiants AWS absents/expirés. Recolle les 3 lignes 'export AWS_...' de Workshop Studio."
echo "Compte AWS : $ACCOUNT, région : $REGION"

# --- Groupe de sécurité (ouvre 80 pour le web, 22 pour le dépannage) -----------
say "Groupe de sécurité"
VPC=$(aws ec2 describe-vpcs --filters Name=isDefault,Values=true --query 'Vpcs[0].VpcId' --output text)
[ "$VPC" != "None" ] || die "Pas de VPC par défaut dans cette région."
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$NAME-sg Name=vpc-id,Values=$VPC \
      --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)
if [ "$SG" = "None" ] || [ -z "$SG" ]; then
  SG=$(aws ec2 create-security-group --group-name $NAME-sg --description "vibeaudit" --vpc-id $VPC \
        --query GroupId --output text)
  aws ec2 authorize-security-group-ingress --group-id $SG \
    --ip-permissions IpProtocol=tcp,FromPort=80,ToPort=80,IpRanges='[{CidrIp=0.0.0.0/0}]' \
                     IpProtocol=tcp,FromPort=22,ToPort=22,IpRanges='[{CidrIp=0.0.0.0/0}]' >/dev/null
fi
echo "Groupe de sécurité : $SG"

# --- Rôle IAM pour Bedrock (facultatif : si refusé, on utilise les creds temporaires) ---
say "Rôle IAM pour Bedrock"
PROFILE_ARG=""
BAKE_CREDS=1
if aws iam create-role --role-name $NAME-ec2 \
     --assume-role-policy-document '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"},"Action":"sts:AssumeRole"}]}' \
     >/dev/null 2>&1; then
  aws iam attach-role-policy --role-name $NAME-ec2 --policy-arn arn:aws:iam::aws:policy/AmazonBedrockFullAccess >/dev/null 2>&1 || true
  aws iam create-instance-profile --instance-profile-name $NAME-ec2 >/dev/null 2>&1 || true
  aws iam add-role-to-instance-profile --instance-profile-name $NAME-ec2 --role-name $NAME-ec2 >/dev/null 2>&1 || true
  echo "Rôle créé : Bedrock accessible sans clé qui expire. (propagation ~15 s)"; sleep 15
  PROFILE_ARG="--iam-instance-profile Name=$NAME-ec2"
  BAKE_CREDS=0
elif aws iam get-instance-profile --instance-profile-name $NAME-ec2 >/dev/null 2>&1; then
  echo "Rôle déjà existant, réutilisé."
  PROFILE_ARG="--iam-instance-profile Name=$NAME-ec2"
  BAKE_CREDS=0
else
  echo "Création de rôle refusée (compte Workshop). On passe les identifiants temporaires au serveur."
  echo "ATTENTION : ces identifiants expirent dans quelques heures. Pour la démo, relance ce script pour rafraîchir."
fi

# --- .env du serveur (contenu injecté dans le script de démarrage) -------------
ACCESS_CODE=$(LC_ALL=C tr -dc 'a-z0-9' </dev/urandom | head -c 8 || echo demo1234)
ENV_LINES="LLM_PROVIDER=bedrock
AWS_REGION=$REGION
BEDROCK_MODEL_ID=${BEDROCK_MODEL_ID:-us.anthropic.claude-sonnet-5}
NPM_AUDIT_MODE=direct
PLATFORM_ACCESS_CODE=$ACCESS_CODE"
[ -n "${SNYK_TOKEN:-}" ] && ENV_LINES="$ENV_LINES
SNYK_TOKEN=$SNYK_TOKEN"
if [ "$BAKE_CREDS" = 1 ]; then
  ENV_LINES="$ENV_LINES
AWS_ACCESS_KEY_ID=$AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY=$AWS_SECRET_ACCESS_KEY
AWS_SESSION_TOKEN=${AWS_SESSION_TOKEN:-}"
fi

# --- Script de démarrage du serveur (user-data, exécuté au boot de l'instance) --
UD=$(mktemp)
cat > "$UD" <<EOF
#!/bin/bash
exec > /var/log/vibeaudit-deploy.log 2>&1
set -x
dnf install -y docker git || yum install -y docker git
systemctl enable --now docker
mkdir -p /opt/app && cd /opt/app
git clone --quiet --depth 1 https://x-access-token:${GH_TOKEN}@github.com/${GH_REPO}.git repo
cd repo
cat > .env <<'ENVEOF'
$ENV_LINES
ENVEOF
docker build -t vibeaudit:latest .
docker run -d --name vibeaudit --restart unless-stopped --env-file .env \
  -p 80:8000 --memory 3g --pids-limit 512 vibeaudit:latest
echo "DEPLOY_DONE"
EOF

# --- Lancement de l'instance ---------------------------------------------------
say "Lancement de l'instance EC2 ($TYPE)"
AMI=$(aws ssm get-parameters --names /aws/service/ami-amazon-linux-latest/al2023-ami-kernel-default-x86_64 \
      --query 'Parameters[0].Value' --output text)
IID=$(aws ec2 run-instances --image-id "$AMI" --instance-type "$TYPE" \
      --security-group-ids "$SG" $PROFILE_ARG \
      --metadata-options "HttpTokens=required,HttpPutResponseHopLimit=2,HttpEndpoint=enabled" \
      --block-device-mappings 'DeviceName=/dev/xvda,Ebs={VolumeSize=30,VolumeType=gp3}' \
      --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=$NAME}]" \
      --user-data "file://$UD" \
      --query 'Instances[0].InstanceId' --output text)
rm -f "$UD"
echo "Instance : $IID"

say "Attente du démarrage..."
aws ec2 wait instance-running --instance-ids "$IID"
IP=$(aws ec2 describe-instances --instance-ids "$IID" \
     --query 'Reservations[0].Instances[0].PublicIpAddress' --output text)

cat <<MSG

-------------------------------------------------------------------
 Instance lancée.  Adresse : http://$IP/
 Code d'accès de la plateforme : $ACCESS_CODE
-------------------------------------------------------------------
 Le serveur installe Docker puis construit l'image : compte ~8 à 12 min.
 Je teste la disponibilité toutes les 20 s ci-dessous.
 En cas de blocage : EC2 > Instances > $NAME > Connect (EC2 Instance Connect),
   puis :  sudo tail -n 50 /var/log/vibeaudit-deploy.log
 Pour tout supprimer ensuite :  bash deploy/aws-teardown.sh
-------------------------------------------------------------------
MSG

for i in $(seq 1 45); do
  if curl -fsS -m 5 "http://$IP/api/health" >/dev/null 2>&1; then
    echo ""; echo "PRÊT -> http://$IP/   (code d'accès : $ACCESS_CODE)"; exit 0
  fi
  printf "."; sleep 20
done
echo ""
echo "Toujours pas de réponse. Ouvre EC2 Instance Connect et lis /var/log/vibeaudit-deploy.log"
echo "Adresse à retester : http://$IP/"
