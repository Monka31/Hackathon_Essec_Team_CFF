# Cahier des charges vibeaudit v0.3

Document de travail interne, Team CFF, hackathon Secure Horizons. But de cette version : connexion GitHub, base de données, correction des failles par Pull Request, et application piégée pour la démo. Chaque brique est indépendante pour que chacun avance de son côté, avec un contrat d'API clair entre elles.

## 1. Rappel de l'architecture cible

- La plateforme tourne sur l'EC2 (Amazon Linux 2023), dans un conteneur Docker, servie en HTTP sur le port 80.
- Backend FastAPI, un seul processus, qui sert l'interface (prototype.html) et l'API.
- Les scanners tournent déjà (Semgrep, gitleaks, npm audit, Snyk, tests passifs, collage Supabase).
- L'IA (Claude via Bedrock) explique les failles et triera les faux positifs.
- On ajoute quatre choses dans cette version :
  - A. Une GitHub App (connexion + clonage privé + droit d'ouvrir des PR)
  - B. Une base SQLite (comptes et historique)
  - C. Le login GitHub de l'utilisateur
  - D. L'agent de correction par Pull Request
  - E. (en parallèle, par un membre de l'équipe) une application piégée pour la démo

Principe de sécurité qui guide tout le document : moindre privilège, jetons courts jamais stockés, aucune modification directe de `main`, l'humain relit et fusionne.

## 2. Brique A : la GitHub App (clé de voûte)

Une seule GitHub App sert trois besoins : identifier l'utilisateur, cloner son repo privé, ouvrir des Pull Requests de correction.

### A.1 Création de la GitHub App

- Aller sur https://github.com/settings/apps puis "New GitHub App".
- Champs :
  - GitHub App name : `vibeaudit` (ou `vibeaudit-cff`)
  - Homepage URL : `http://35.87.147.57/`
  - Callback URL : `http://35.87.147.57/api/auth/github/callback`
  - Cocher "Request user authorization (OAuth) during installation"
  - Webhook : décocher "Active" (pas de webhook pour le hackathon)
- Permissions (Repository permissions) :
  - Metadata : Read-only (obligatoire, automatique)
  - Contents : Read and write (read pour cloner, write pour créer branche et commit)
  - Pull requests : Read and write
  - (rien d'autre)
- Account permissions : aucune.
- "Where can this GitHub App be installed ?" : Any account (pour que n'importe qui puisse tester son projet).

### A.2 Secrets à récupérer après création

- App ID (nombre)
- Client ID
- Générer un "Client secret" (pour le login OAuth)
- Générer et télécharger une "Private key" (fichier .pem, pour les jetons d'installation)
- Installer l'App sur son propre compte, choisir le(s) repo(s), et noter l'Installation ID (visible dans l'URL des settings d'installation)

### A.3 Les deux flux d'authentification à comprendre

- Flux 1, identité de l'utilisateur (login) : OAuth web classique avec Client ID / Client secret. Sert uniquement à savoir qui se connecte. On récupère un token utilisateur, on appelle `GET /user`, on garde id, login, nom, avatar.
- Flux 2, accès au repo (clone + PR) : jeton d'installation. On signe un JWT avec la clé privée .pem, on appelle `POST /app/installations/{installation_id}/access_tokens`, on obtient un jeton court (1 h) limité aux repos installés et aux permissions ci-dessus. Ce jeton sert à cloner (`https://x-access-token:TOKEN@github.com/owner/repo.git`) et à créer branche, commit, PR.
- Important : le jeton d'installation est redemandé à la volée à chaque besoin, jamais stocké en base.

### A.4 Variables d'environnement (sur l'EC2)

```
GITHUB_APP_ID=...
GITHUB_APP_CLIENT_ID=...
GITHUB_APP_CLIENT_SECRET=...
GITHUB_APP_PRIVATE_KEY_PATH=/opt/app/secrets/vibeaudit.pem
APP_BASE_URL=http://35.87.147.57
```

- Mettre le fichier .pem sur l'EC2 dans `/opt/app/secrets/vibeaudit.pem`, en `chmod 600`, monté en lecture seule dans le conteneur.
- Le .pem et le client secret ne sont JAMAIS commités. Les ajouter à `.gitignore`.

## 3. Brique B : la base de données SQLite

### B.1 Emplacement et persistance

- Fichier unique : `/data/vibeaudit.db` dans le conteneur.
- Monté sur l'EC2 via un volume Docker : `-v /opt/app/data:/data` (à ajouter dans `update.sh` au `docker run`).
- On utilise `sqlite3` de la librairie standard Python, pas d'ORM lourd.

### B.2 Schéma (version hackathon, volontairement simple)

```sql
CREATE TABLE users (
  id INTEGER PRIMARY KEY,
  github_id INTEGER UNIQUE NOT NULL,
  login TEXT NOT NULL,
  name TEXT,
  avatar_url TEXT,
  created_at TEXT NOT NULL
);

CREATE TABLE sessions (
  token TEXT PRIMARY KEY,          -- token aléatoire, mis dans un cookie httpOnly
  user_id INTEGER NOT NULL REFERENCES users(id),
  expires_at TEXT NOT NULL
);

CREATE TABLE audits (
  id TEXT PRIMARY KEY,             -- l'audit_id déjà généré aujourd'hui
  user_id INTEGER REFERENCES users(id),  -- nullable : audit anonyme possible
  repo_url TEXT,
  app_url TEXT,
  score INTEGER,
  status TEXT,                     -- queued | running | done | error
  created_at TEXT NOT NULL
);
```

### B.3 Règles

- Jamais de jeton GitHub ni de secret en base. On stocke seulement l'identité publique et l'historique.
- L'audit anonyme (sans login) reste possible : `user_id` nullable. Le login sert à retrouver son historique et à proposer la correction.
- Cookie de session : httpOnly. Limite connue : l'EC2 est en HTTP, donc le cookie n'est pas en `Secure`. Acceptable pour la démo, à signaler comme limite (passage HTTPS plus tard).

## 4. Brique C : le login GitHub de l'utilisateur

### C.1 Endpoints à exposer

- `GET /api/auth/github/login` : redirige vers GitHub (OAuth, scope identité). Construit l'URL d'autorisation avec `client_id`, `redirect_uri`, et un `state` aléatoire anti-CSRF.
- `GET /api/auth/github/callback` : GitHub renvoie un `code`. On l'échange contre un token utilisateur, on appelle `GET /user`, on crée ou met à jour la ligne `users`, on crée une `sessions`, on pose le cookie, puis on redirige vers `/`.
- `POST /api/auth/logout` : supprime la session.
- `GET /api/me` : renvoie l'utilisateur courant à partir du cookie (ou `null`).

### C.2 Côté interface (prototype.html)

- Remplacer le stub actuel `/api/auth/signup` par un vrai bouton "Se connecter avec GitHub" qui pointe vers `/api/auth/github/login`.
- Afficher l'avatar et le nom quand `GET /api/me` renvoie un utilisateur.
- L'écran d'historique liste les audits de l'utilisateur (nouvel endpoint `GET /api/me/audits`).

### C.3 Sécurité

- Vérifier le `state` au retour (anti-CSRF).
- Le `state` est à usage unique, stocké en session temporaire ou cookie court.

## 5. Brique D : l'agent de correction par Pull Request

C'est la brique sensible. Règle absolue : on n'écrit jamais sur `main`, on ouvre une PR, l'humain relit et fusionne. Pas de fusion automatique.

### D.1 Parcours utilisateur

- Après l'audit, chaque finding a un bouton "Proposer un correctif".
- Au clic : l'agent génère le correctif, crée une branche, commit, ouvre une PR, et renvoie le lien de la PR.
- L'interface affiche le diff proposé et le lien PR. L'utilisateur va sur GitHub relire et fusionner lui-même.

### D.2 Flux technique (via l'API GitHub, sans clone ni push)

1. Récupérer le jeton d'installation (brique A, flux 2).
2. `GET /repos/{owner}/{repo}/git/ref/heads/{branche_defaut}` pour le SHA du dernier commit.
3. `POST /repos/{owner}/{repo}/git/refs` pour créer `refs/heads/vibeaudit/fix-{id}`.
4. Pour chaque fichier modifié : `GET /repos/.../contents/{path}?ref=branche` (récupère le `sha` et le contenu), appliquer le correctif, puis `PUT /repos/.../contents/{path}` avec le nouveau contenu, le `sha`, et la branche.
5. `POST /repos/{owner}/{repo}/pulls` pour ouvrir la PR de la branche vers la branche par défaut. Jamais de merge.

### D.3 Périmètre des correctifs (volontairement restreint pour la fiabilité en démo)

On ne corrige automatiquement que des cas où le correctif est fiable et ne casse pas le build :

- Secret en dur : remplacer la valeur littérale par `process.env.NOM`, ajouter une entrée dans `.env.example`, et un commentaire. Le secret réel n'est jamais réécrit dans le diff.
- Dépendance vulnérable : monter la version dans `package.json` à la version corrigée indiquée par l'advisory.
- En-tête de sécurité manquant : ajouter la configuration (bloc `headers` dans `vercel.json`, ou middleware).
- Table Supabase sans RLS : générer un fichier de migration `.sql` (activation RLS + policy) ajouté dans la PR. On ne l'exécute pas, l'humain l'applique. On ne touche pas à la base directement.

- Pour tout le reste : l'agent écrit une suggestion en commentaire dans la PR, sans modifier le code (trop risqué en live).
- Le correctif de code est proposé par Claude (Bedrock) à partir du finding, puis formaté en diff. On garde un correctif par PR pour que ce soit relisible.

### D.4 Endpoints à exposer

- `POST /api/audits/{audit_id}/findings/{finding_id}/fix` : lance la création de la PR, renvoie `{ pr_url, branch, diff }`. (Remplace le stub actuel qui ne fait rien.)
- Vérifier que l'utilisateur connecté a bien les droits sur le repo (installation présente) avant d'agir.

### D.5 Garde-fous (ce qui fait le livrable "l'humain garde le contrôle")

- Aucune écriture sur `main`, aucune fusion automatique.
- Une PR = un correctif, titre et description clairs générés par l'outil.
- Permissions GitHub minimales (contents + pull requests seulement).
- Jeton d'installation court, jamais stocké.
- Case de consentement du propriétaire déjà présente, à conserver.

## 6. Brique E : l'application piégée pour la démo (confiée à un membre de l'équipe)

But : un petit projet qui déclenche CHAQUE scanner, pour une démo riche et une vraie matière à corriger. Repo GitHub séparé, idéalement déployable sur Vercel pour avoir une URL en ligne.

À planter, un par scanner :

- Secret en dur (déclenche gitleaks) : une clé type `const STRIPE_KEY = "sk_live_...."` factice dans un fichier source.
- Dépendance vulnérable connue (déclenche npm audit / Snyk) : épingler dans `package.json` une version ancienne connue vulnérable (ex. une vieille version de `lodash` ou `axios`).
- Faille de code (déclenche Semgrep) : une injection SQL par concaténation, ou un `eval()` sur une entrée utilisateur, ou `dangerouslySetInnerHTML` avec entrée non filtrée.
- En-tête de sécurité manquant (déclenche le test passif) : déploiement sans `Content-Security-Policy` ni `X-Frame-Options` (c'est le cas par défaut, donc ne rien configurer).
- Table Supabase sans RLS (déclenche le collage advisor) : créer une table sans Row Level Security, et récupérer le rapport Security Advisor à coller en démo.

Livrables attendus de cette personne :

- Le lien du repo GitHub (public, ou on installe la GitHub App dessus).
- L'URL Vercel en ligne.
- Le rapport Supabase Security Advisor (copié/collé) si une table est concernée.

Contrainte : failles réalistes mais inoffensives (données factices, pas de vrai secret, pas de vraie base sensible).

## 7. Répartition du travail (chacun de son côté)

- Membre 1 (Marco, avec Claude) : brique A (GitHub App, config) + brique C (login).
- Membre 2 (Claude côté code) : brique B (SQLite) + brique D (agent de correction par PR).
- Membre 3 (l'ami) : brique E (application piégée).

Ces trois chantiers sont indépendants grâce aux contrats d'API ci-dessous. On intègre à la fin.

## 8. Contrat d'intégration entre les briques

Pour que le travail en parallèle se recolle sans friction :

- La base (B) expose des fonctions simples : `get_or_create_user`, `create_session`, `get_user_by_session`, `save_audit`, `list_user_audits`.
- Le login (C) écrit dans `users` et `sessions` via ces fonctions, et rien d'autre.
- L'agent de correction (D) a besoin d'une fonction `get_installation_token(owner, repo)` fournie par la brique A. Tant qu'elle n'existe pas, D peut se tester avec un token mis en variable d'environnement.
- L'interface attend déjà le format de finding actuel : on ne change pas ce format, on ajoute seulement `pr_url` et `diff` dans la réponse de l'endpoint fix.
- L'app piégée (E) n'a aucune dépendance technique avec le reste : elle fournit juste un repo et une URL.

## 9. Récapitulatif des variables d'environnement (EC2)

```
# IA (déjà en place)
LLM_PROVIDER=bedrock
BEDROCK_MODEL_ID=us.anthropic.claude-sonnet-5
AWS_REGION=us-west-2

# GitHub App (nouveau)
GITHUB_APP_ID=...
GITHUB_APP_CLIENT_ID=...
GITHUB_APP_CLIENT_SECRET=...
GITHUB_APP_PRIVATE_KEY_PATH=/opt/app/secrets/vibeaudit.pem
APP_BASE_URL=http://35.87.147.57

# Session
SESSION_SECRET=<chaine aleatoire longue>
```

## 10. Ordre d'avancement conseillé

1. Marco crée la GitHub App et récupère les secrets (brique A.1 et A.2). C'est le préalable à tout le reste.
2. En parallèle, l'ami commence l'app piégée (brique E).
3. Claude code la base SQLite (B) puis le login (C), puis l'agent de correction (D).
4. Intégration : on branche le login sur l'interface, on teste un audit complet de l'app piégée, puis une PR de correction de bout en bout.

## 11. Limites connues à assumer devant le jury

- EC2 en HTTP, pas HTTPS : cookies non `Secure`, à migrer plus tard.
- Correction automatique limitée à quelques types de failles fiables ; le reste est suggéré en commentaire de PR.
- Pas de couverture de l'authentification applicative, du contrôle d'accès fin, ni de la logique métier (analyse statique et passive, pas de test d'intrusion actif).
- DAST seulement si configuré.
