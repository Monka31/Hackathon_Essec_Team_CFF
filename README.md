# Vouch

**Security a founder can actually act on.**
Stacked, explained, vouched for.

Vouch is a security audit and remediation tool for vibe-coded apps. You point it at a GitHub repository, a ZIP, or a live URL. It audits the project across three layers, explains every finding in plain language, and opens a GitHub pull request that fixes it, which a human reviews and merges. It never runs the audited code and never merges on its own.

Built by **Team CFF** at **Secure Horizons** (UTOPIA x KRYPTOSPHERE x ESSEC MetaLab), ESSEC Cergy, 10-11 October 2026.
Track 03 - Open Track ("Uncharted Frontiers"). Internal code name: `vibeaudit`.

Live demo: http://35.87.147.57

---

## The problem

- Anyone can ship a real app in a weekend with AI tools (Lovable, Cursor, v0, Bolt), with real users and real data on it.
- These apps ship with the same holes: exposed secrets, no database access rules, vulnerable dependencies, missing security headers.
- The people shipping them have no CISO and no security team, and cannot read tools built for security engineers.
- Detection already exists. Understanding what it means, and actually fixing it, for a non-expert, does not.

## The solution

Vouch reads a project as **one pile of three layers** and vouches for the top one.

- **Code** - what you and your AI wrote: secrets, injections, risky patterns.
- **Dependencies** - the packages you stand on: known vulnerabilities.
- **Live app** - the app as people use it: checked, then vouched for.

Every finding is explained at four levels (from founder to expert), rated for real exploitability, and turned into a concrete fix proposed as a reviewed pull request.

## What makes it different

- **Remediation, not just detection.** Vouch does not stop at a report. For dependency issues it updates `package.json`, regenerates `package-lock.json`, and loops `npm audit fix` until `npm audit` is clean. For code issues it rewrites the file and re-scans it.
- **Every fix is verified before the PR opens.** A dependency fix is re-audited with `npm audit`; a code fix is re-scanned with Semgrep (before/after). A fix that fails the check is never proposed.
- **Human in the loop.** The agent proposes, a person reviews the diff and merges. Nothing changes on the default branch until they do.
- **Readable and honest.** A score out of 100 summarizes the state (it is a summary, not a certification). Vouch distinguishes real risk from noise (a public Supabase anon key is not a leak; the database access rules are what matter).
- **Safe by design.** The audited code is never executed, secrets are masked everywhere in reports, and repos are cloned read-only with short-lived tokens.

---

## How it works

1. **Connect a target** - a GitHub repo (via the Vouch GitHub App), a URL, or a ZIP. The repo is cloned read-only with a short-lived installation token.
2. **Scan in parallel** across the three layers (see the table below).
3. **Normalize and redact** - results are normalized to a common format and any detected secret is masked (first 4 characters only).
4. **Merge and score** - duplicates across scanners are merged by a stable fingerprint; a score out of 100 is computed.
5. **Explain with AI** - each finding is explained at four levels, with a judgment on real exploitability and a false-positive flag. Prompt injection in the audited code is detected and ignored.
6. **Fix as a pull request** - an agent prepares the fix, verifies it, and opens one pull request on a dedicated branch for a human to review and merge.

## What is scanned

| Scanner | What it finds | Layer | Requirement |
|---|---|---|---|
| Semgrep | code flaws (injections, eval, risky patterns) | code | bundled |
| Snyk Code | code flaws (SAST) | code | `snyk auth` |
| Gitleaks | secrets in code and git history | code | bundled |
| TruffleHog | verified live secrets | code | bundled |
| npm audit | vulnerable dependencies | dependencies | `package-lock.json` |
| Snyk Open Source | vulnerable dependencies (SCA) | dependencies | `snyk auth` |
| Supabase Advisor | tables without RLS, exposed functions | database | token + ref in `.env` |
| Passive web tests | HTTPS, security headers, exposed `.env`/`.git`, keys in the JS | live app | none |
| Snyk API & Web (DAST) | dynamic scan of the live app | live app | `PROBELY_API_KEY` |
| Active probes | reflected XSS marker, open redirect, CORS, verbose errors | live app | owner-authorized |

A scanner that is missing or fails is reported in the audit and never blocks the others.

## The fix engine

- **Dependencies.** Vouch establishes a valid lockfile with npm, applies the patched versions, and loops `npm audit fix` (then `--force` as a last resort) until `npm audit` is clean. Each finding ends as **verified** (confirmed clean) or **still vulnerable** (no patch without a breaking change) - never "do it yourself".
- **Code.** The AI rewrites the affected file; the change is re-scanned with Semgrep before and after to confirm the issue is gone and no new one was introduced.
- **Guardrails.** Lockfiles are never hand-written, JSON is validated before commit, file paths are checked, and the pull request is opened on a dedicated branch (never auto-merged).

---

## Architecture

```
vibeaudit/
  __main__.py     CLI entry points: scan and serve
  config.py       configuration and environment handling
  scanners/       one file per tool, each normalizing its output to a common format
  core/           common model, duplicate merge, scoring, secret redaction, parallel runner
  llm/            AI explanations and the fix agent (Claude via Amazon Bedrock)
  report/         HTML report (template) and JSON
  web/            platform: FastAPI app, GitHub App, database, fix engine, single-page UI
deploy/           Dockerfile helpers and AWS EC2 scripts (launch, update, teardown)
Dockerfile        image with the app and every scanner, ready for EC2
requirements.txt  Python dependencies
```

Scoring: every project starts at 100; each open finding removes points by severity (critical -25, high -10, medium -3, low -1), capped at 40 points per category. Every exposed secret is critical. The score summarizes what was found; it is not a certification or full security coverage.

## Tech stack

- **AI:** Claude via Amazon Bedrock (explanations, exploitability judgment, fix agent, with forced structured output).
- **Backend:** Python, FastAPI, SQLite.
- **Integration:** GitHub App (short-lived tokens, read-only clone, pull requests) and GitHub OAuth login.
- **Security tooling:** Semgrep, Gitleaks, TruffleHog, npm audit, Snyk Code & Open Source, Snyk API & Web (DAST), Supabase Security Advisor.
- **Infrastructure:** AWS EC2, Docker.

---

## Installation (local)

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env        # then fill in the values you need

brew install semgrep gitleaks         # macOS; or use the Docker image
npm install -g snyk && snyk auth      # optional, for the Snyk scanners
```

## Usage

**Web platform** (form: GitHub link or app URL):

```bash
source .venv/bin/activate
python -m vibeaudit serve
# open http://127.0.0.1:8000
```

**Command line:**

```bash
python -m vibeaudit scan ~/path/to/project --url https://my-app.com --out reports/report.html
```

Options:
- `--skip snyk_code,snyk_deps` to save Snyk quota
- `--only gitleaks,npm_audit` for a quick scan
- `--json path.json` to choose where the JSON is written

The JSON has the same structure as the HTML; it is what the interface reads.

## Deployment (AWS EC2)

The whole platform runs in one Docker container (the app plus every scanner). See `deploy/README-AWS.md` for the full walkthrough. To update a running server:

```bash
sudo bash /opt/app/repo/deploy/update.sh
```

## Configuration

Copy `.env.example` to `.env` and fill in what you need. Nothing is required to run a basic audit; each key simply unlocks a capability.

| Variable | Unlocks |
|---|---|
| `LLM_PROVIDER`, `AWS_REGION`, `BEDROCK_MODEL_ID` | the AI explanations and fix agent (Amazon Bedrock) |
| `GITHUB_APP_ID`, `GITHUB_APP_CLIENT_ID`, `GITHUB_APP_CLIENT_SECRET`, `GITHUB_APP_PRIVATE_KEY_B64` | GitHub login and pull requests |
| `SNYK_TOKEN`, `SNYK_ORG` | the Snyk Code and Open Source scanners |
| `SUPABASE_ACCESS_TOKEN`, `SUPABASE_PROJECT_REF` | the Supabase RLS advisor |
| `PROBELY_API_KEY` | the Snyk API & Web (DAST) scanner |

## Repository security

Secrets are never committed: `.env` is ignored, and every commit is scanned by `ggshield` (GitGuardian) through a pre-commit hook. Reports mask every secret to its first four characters.

---

## Known limitations

- Verified dependency fixes currently target **npm** (`package-lock.json`); yarn, pnpm and bun lockfiles are bumped in the manifest but need a local install.
- Verified fixes require the server to reach the **npm registry**; without it, Vouch falls back to a reviewed manifest change.
- Web tests are **non-destructive and owner-authorized**, not a full penetration test.
- Some findings (transitive CVEs that need a major upgrade) are **flagged honestly** rather than auto-fixed.
- Focused today on the **JavaScript / TypeScript + Supabase** stack typical of vibe-coded apps.
- The score is a summary of what was found, not a certification or a guarantee of full coverage.

## Team

**Team CFF** - Secure Horizons, ESSEC Cergy, October 2026.
