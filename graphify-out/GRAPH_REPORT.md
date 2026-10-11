# Graph Report - Hackathon_Essec_Team_CFF  (2026-10-11)

## Corpus Check
- 44 files · ~35,849 words
- Verdict: corpus is large enough that graph structure adds value.
- Unclassified: 8 file(s) not represented in the graph (top: (none) 7, .example 1)

## Summary
- 475 nodes · 1174 edges · 25 communities (17 shown, 8 thin omitted)
- Extraction: 97% EXTRACTED · 3% INFERRED · 0% AMBIGUOUS · INFERRED: 35 edges (avg confidence: 0.94)
- Token cost: 0 input · 0 output

## Graph Freshness
- Built from commit: `a8799402`
- Run `git rev-parse HEAD` and compare to check if the graph is stale.
- Run `graphify update .` after code changes (no API cost).

## Community Hubs (Navigation)
- base.py
- app.py
- jobs.py
- Finding
- explain.py
- __main__.py
- web/db.py
- github_app.py
- adapter.py
- vibeaudit/db.py
- JobStore
- Cahier des charges vibeaudit v0.3
- Hackathon Essec - Team CFF
- Mise en ligne sur AWS (EC2 + Docker)
- aws-launch.sh
- aws-teardown.sh
- FindingList
- Security fixes proposed by vibeaudit
- ec2-user-data.sh
- deploy/start.sh
- update.sh
- start.sh

## God Nodes (most connected - your core abstractions)
1. `Finding` - 38 edges
2. `Evidence` - 20 edges
3. `ScannerError` - 20 edges
4. `_current_user()` - 17 edges
5. `ScannerSkipped` - 15 edges
6. `_conn()` - 15 edges
7. `deploy()` - 15 edges
8. `run_cmd()` - 14 edges
9. `read_snippet()` - 14 edges
10. `JobStore` - 14 edges

## Surprising Connections (you probably didn't know these)
- `1. Rappel de l'architecture cible` --references--> `main()`  [INFERRED]
  CAHIER-DES-CHARGES.md → vibeaudit/__main__.py
- `C.1 Endpoints à exposer` --references--> `client_id()`  [INFERRED]
  CAHIER-DES-CHARGES.md → vibeaudit/web/github_app.py
- `D.5 Garde-fous (ce qui fait le livrable "l'humain garde le contrôle")` --references--> `main()`  [INFERRED]
  CAHIER-DES-CHARGES.md → vibeaudit/__main__.py
- `5. Brique D : l'agent de correction par Pull Request` --references--> `main()`  [INFERRED]
  CAHIER-DES-CHARGES.md → vibeaudit/__main__.py
- `8. Contrat d'intégration entre les briques` --references--> `get_or_create_user()`  [INFERRED]
  CAHIER-DES-CHARGES.md → vibeaudit/db.py

## Import Cycles
- None detected.

## Communities (25 total, 8 thin omitted)

### Community 0 - "base.py"
Cohesion: 0.10
Nodes (52): CompletedProcess, json, os, pathlib, Evidence, Preuve brute : ce qu'un scanner précis a remonté (choix B)., find_line(), Exception (+44 more)

### Community 1 - "app.py"
Cohesion: 0.09
Nodes (56): delete, fastapi, fastapi_responses, get, io, middleware, ParseResult, post (+48 more)

### Community 2 - "jobs.py"
Cohesion: 0.10
Nodes (34): concurrent_futures, dataclasses, hashlib, Progress, shutil, subprocess, tempfile, time (+26 more)

### Community 3 - "Finding"
Cohesion: 0.10
Nodes (30): ipaddress, socket, urllib_error, urllib_parse, urllib_request, Finding, Any, Clé de fusion des doublons (choix E). (+22 more)

### Community 4 - "explain.py"
Cohesion: 0.11
Nodes (33): 0 = critique (le plus grave), 3 = basse., severity_rank(), _anthropic(), _bedrock(), complete(), _fake(), LLMError, LLMUnavailable (+25 more)

### Community 5 - "__main__.py"
Cohesion: 0.09
Nodes (30): argparse, 5. Brique D : l'agent de correction par Pull Request, D.1 Parcours utilisateur, D.2 Flux technique (via l'API GitHub, sans clone ni push), D.3 Périmètre des correctifs (volontairement restreint pour la fiabilité en démo), D.4 Endpoints à exposer, D.5 Garde-fous (ce qui fait le livrable "l'humain garde le contrôle"), dotenv (+22 more)

### Community 6 - "web/db.py"
Cohesion: 0.12
Nodes (29): Row, secrets, threading, audit_owner(), _conn(), create_session(), delete_audit_row(), delete_project() (+21 more)

### Community 7 - "github_app.py"
Cohesion: 0.14
Nodes (29): base64, jwt, requests, deploy(), _app_headers(), app_id(), app_jwt(), app_slug() (+21 more)

### Community 8 - "adapter.py"
Cohesion: 0.11
Nodes (23): math, re, _entropy(), _looks_like_token(), mask(), Any, Masquage des secrets (choix F) : notre propre rapport ne doit jamais devenir…, Une chaîne longue, avec lettres et chiffres, aléatoire, et qui n'est pas un… (+15 more)

### Community 9 - "vibeaudit/db.py"
Cohesion: 0.14
Nodes (27): 8. Contrat d'intégration entre les briques, contextlib, datetime, sqlite3, create_session(), delete_session(), get_audit(), get_conn() (+19 more)

### Community 10 - "JobStore"
Cohesion: 0.21
Nodes (10): audit_log(), clone_repo(), _dir_size_mb(), Job, JobStore, _now(), Any, Path (+2 more)

### Community 11 - "Cahier des charges vibeaudit v0.3"
Cohesion: 0.10
Nodes (20): 10. Ordre d'avancement conseillé, 11. Limites connues à assumer devant le jury, 1. Rappel de l'architecture cible, 2. Brique A : la GitHub App (clé de voûte), 3. Brique B : la base de données SQLite, 4. Brique C : le login GitHub de l'utilisateur, 6. Brique E : l'application piégée pour la démo (confiée à un membre de l'équipe), 7. Répartition du travail (chacun de son côté) (+12 more)

### Community 12 - "Hackathon Essec - Team CFF"
Cohesion: 0.18
Nodes (10): Architecture, Ce qui est scanné, Démo, Equipe, Hackathon Essec - Team CFF, Installation (une fois), Problème, Solution (+2 more)

### Community 13 - "Mise en ligne sur AWS (EC2 + Docker)"
Cohesion: 0.29
Nodes (6): 1. Rôle IAM pour Bedrock (si tu as le droit de créer un rôle), 2. Lancer l'instance, 3. Configurer et démarrer, 4. Mettre à jour après un changement de code, Dépannage, Mise en ligne sur AWS (EC2 + Docker)

### Community 14 - "aws-launch.sh"
Cohesion: 0.60
Nodes (4): AWS_DEFAULT_REGION, die(), say(), aws-launch.sh script

### Community 15 - "aws-teardown.sh"
Cohesion: 0.67
Nodes (3): AWS_DEFAULT_REGION, say(), aws-teardown.sh script

### Community 16 - "FindingList"
Cohesion: 0.50
Nodes (3): list, FindingList, Liste de failles + une note pour le rapport (ex : nombre de fichiers analysés).

## Knowledge Gaps
- **39 isolated node(s):** `AWS_DEFAULT_REGION`, `AWS_DEFAULT_REGION`, `ec2-user-data.sh script`, `start.sh script`, `update.sh script` (+34 more)
  These have ≤1 connection - possible missing edges or undocumented components. (Counts symbols only; 156 node(s) total have ≤1 connection when file, concept and rationale nodes are included.)
- **8 thin communities (<3 nodes) omitted from report** — run `graphify query` to explore isolated nodes.

## Suggested Questions
_Questions this graph is uniquely positioned to answer:_

- **Why does `Cahier des charges vibeaudit v0.3` connect `Cahier des charges vibeaudit v0.3` to `vibeaudit/db.py`, `__main__.py`?**
  _High betweenness centrality (0.060) - this node is a cross-community bridge._
- **Why does `main()` connect `__main__.py` to `Cahier des charges vibeaudit v0.3`?**
  _High betweenness centrality (0.056) - this node is a cross-community bridge._
- **Why does `Finding` connect `Finding` to `base.py`, `jobs.py`?**
  _High betweenness centrality (0.048) - this node is a cross-community bridge._
- **Are the 12 inferred relationships involving `Finding` (e.g. with `merge_findings()` and `build_report()`) actually correct?**
  _`Finding` has 12 INFERRED edges - model-reasoned connections that need verification._
- **What connects `AWS_DEFAULT_REGION`, `AWS_DEFAULT_REGION`, `ec2-user-data.sh script` to the rest of the system?**
  _39 weakly-connected nodes found - possible documentation gaps or missing edges._
- **Should `base.py` be split into smaller, more focused modules?**
  _Cohesion score 0.09661016949152543 - nodes in this community are weakly interconnected._
- **Should `app.py` be split into smaller, more focused modules?**
  _Cohesion score 0.08709273182957393 - nodes in this community are weakly interconnected._