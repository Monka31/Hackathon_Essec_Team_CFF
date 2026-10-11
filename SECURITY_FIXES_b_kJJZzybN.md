# Security fixes proposed by Syberia

This pull request was opened by Syberia on a dedicated branch. Review the diff and merge
what you agree with. Nothing on your default branch changed until you merge.
AI-generated code changes are proposals: automated tests and a post-fix security scan were not run.

- Files changed with a proposed fix: 1
- Items reviewed in this PR: 3

## Server-Side Request Forgery (SSRF)  (HIGH)
- Location: `vibeaudit/web/app.py:305`
- Status: an AI-proposed edit was made to this file; this finding is not verified.
- Problem: The flagged line extracts owner/repo from a user-supplied repo_url and uses it to fetch a GitHub token; elsewhere (per Snyk's data flow) this URL or related app_url ends up as the target of requests.get(), which is the actual SSRF sink. Exploitation requires an authenticated attacker able to submit repo_url/app_url pointing at an internal address, a cloud metadata endpoint, or a crafted redirect t

## Path Traversal  (HIGH)
- Location: `vibeaudit/web/app.py:318`
- Status: an AI-proposed edit was made to this file; this finding is not verified.
- Problem: Unsanitized input from an HTTP parameter flows into shutil.rmtree, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to remove arbitrary files.

## Path Traversal  (HIGH)
- Location: `vibeaudit/web/app.py:328`
- Status: an AI-proposed edit was made to this file; this finding is not verified.
- Problem: Unsanitized input from an HTTP parameter flows into shutil.rmtree, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to remove arbitrary files.
