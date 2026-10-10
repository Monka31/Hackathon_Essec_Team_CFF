#!/usr/bin/env bash
# Supprime tout ce que aws-launch.sh a créé (instance, groupe de sécurité, rôle).
# À lancer dans le même terminal (identifiants AWS exportés).
set -uo pipefail
REGION="${AWS_REGION:-us-west-2}"; export AWS_DEFAULT_REGION="$REGION"
NAME="vibeaudit"
say(){ printf "\n==> %s\n" "$*"; }

say "Instance(s)"
IDS=$(aws ec2 describe-instances \
  --filters Name=tag:Name,Values=$NAME "Name=instance-state-name,Values=pending,running,stopping,stopped" \
  --query 'Reservations[].Instances[].InstanceId' --output text)
if [ -n "$IDS" ]; then
  echo "Terminaison : $IDS"
  aws ec2 terminate-instances --instance-ids $IDS >/dev/null
  aws ec2 wait instance-terminated --instance-ids $IDS
fi

say "Rôle IAM"
aws iam remove-role-from-instance-profile --instance-profile-name $NAME-ec2 --role-name $NAME-ec2 2>/dev/null || true
aws iam delete-instance-profile --instance-profile-name $NAME-ec2 2>/dev/null || true
aws iam detach-role-policy --role-name $NAME-ec2 --policy-arn arn:aws:iam::aws:policy/AmazonBedrockFullAccess 2>/dev/null || true
aws iam delete-role --role-name $NAME-ec2 2>/dev/null || true

say "Groupe de sécurité"
SG=$(aws ec2 describe-security-groups --filters Name=group-name,Values=$NAME-sg \
     --query 'SecurityGroups[0].GroupId' --output text 2>/dev/null || echo None)
[ "$SG" != "None" ] && [ -n "$SG" ] && aws ec2 delete-security-group --group-id "$SG" 2>/dev/null || true

echo ""; echo "Nettoyage terminé."
