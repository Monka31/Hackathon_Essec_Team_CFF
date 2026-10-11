# Security fixes proposed by Syberia

This pull request was opened by Syberia on a dedicated branch. Review the diff and merge
what you agree with. Nothing on your default branch changed until you merge.

- Files changed with a proposed fix: 1
- Items reviewed in this PR: 3

## Server-Side Request Forgery (SSRF)  (HIGH)
- Location: `vibeaudit/web/app.py:325`
- Status: a fix was applied to this file in this pull request (review the diff).
- Problem: This is a classic CWE-918 SSRF pattern: untrusted input (repo_url/app_url from an HTTP parameter) flows toward a network request without validation. In the shown code, the URL is split into parts for token lookup, but the broader concern is any point downstream where repo_url or app_url is passed to requests.get or similar. To fix, enforce an allowlist of expected hosts (e.g. only github.com and k

## Path Traversal  (HIGH)
- Location: `vibeaudit/web/app.py:338`
- Status: a fix was applied to this file in this pull request (review the diff).
- Problem: Unsanitized input from an HTTP parameter flows into shutil.rmtree, where it is used as a path. This may result in a Path Traversal vulnerability and allow an attacker to remove arbitrary files.

## Path Traversal  (HIGH)
- Location: `vibeaudit/web/app.py:348`
- Status: a fix was applied to this file in this pull request (review the diff).
- Problem: The vulnerability chain is: HTTP parameter audit_id -> db.delete_audit_row (authorization check) -> STORE.delete(audit_id) -> likely os.path.join(base_dir, audit_id) -> shutil.rmtree(path). Even though delete_audit_row checks user ownership in the DB, this does not prevent path traversal if STORE.delete constructs the filesystem path directly from the unsanitized id. Exploitation requires audit_id
