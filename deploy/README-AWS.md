# Mise en ligne sur AWS (EC2 + Docker)

Région : **us-west-2** (celle du compte Workshop). Durée : 20 à 30 minutes, dont 10 de construction de l'image.

## 1. Rôle IAM pour Bedrock (si tu as le droit de créer un rôle)

IAM > Roles > Create role
- Trusted entity : **AWS service**, use case **EC2**
- Permission : `AmazonBedrockFullAccess` (ou une politique limitée à `bedrock:InvokeModel` et `bedrock:Converse`)
- Nom : `vibeaudit-ec2`

Sans ce droit : on passera les identifiants temporaires dans le `.env` (ils expirent, à recoller).

## 2. Lancer l'instance

EC2 > Launch instance
- Nom : `vibeaudit`
- Image : **Amazon Linux 2023** (x86_64)
- Type : **t3.large** (2 vCPU, 8 Go : Semgrep est gourmand)
- Key pair : "Proceed without a key pair" (on se connectera par le navigateur avec EC2 Instance Connect)
- Network : **Create security group**, autoriser **SSH (22)** et **HTTP (80)** depuis Anywhere
- Storage : **30 Go**
- Advanced details :
  - IAM instance profile : `vibeaudit-ec2` (étape 1)
  - **Metadata response hop limit : 2** (sinon le conteneur Docker ne récupère pas les droits Bedrock du rôle)
  - User data : coller le contenu de `deploy/ec2-user-data.sh`

Launch, puis attendre 2 minutes.

## 3. Configurer et démarrer

EC2 > Instances > vibeaudit > **Connect** > EC2 Instance Connect > Connect (un terminal s'ouvre dans le navigateur)

```
cd ~/vibeaudit
cp .env.example .env
nano .env          # remplir SNYK_TOKEN, PROBELY_API_KEY, PLATFORM_ACCESS_CODE, NPM_AUDIT_MODE...
bash deploy/start.sh
```

Le script affiche l'adresse publique : `http://<IP>/`.

## 4. Mettre à jour après un changement de code

```
cd ~/vibeaudit && bash deploy/start.sh
```

## Dépannage

- Voir les logs : `sudo docker logs -f vibeaudit`
- Le site ne répond pas de l'extérieur : vérifier la règle HTTP (80) du security group
- Bedrock "Unable to locate credentials" : rôle IAM non attaché ou hop limit à 1
- Le compte Workshop est supprimé à la fin de l'événement : tout est à redéployer sur un compte AWS à vous ensuite
