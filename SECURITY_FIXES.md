# Security fixes proposed by vibeaudit

This pull request was opened by vibeaudit. It only ADDS files (recommendations and
example migrations). Nothing in your existing code was changed and nothing was deployed.
Review each item below, apply what you agree with, then merge.

## Dynamic urllib use detected  (MEDIUM)
- Location: `vibeaudit/llm/client.py:113`
- Recommended fix:
  - Review how the Request object's URL is constructed above line 113 to confirm whether any part is user- or tenant-controllable.
  - Add explicit validation that the scheme is 'https' (reject file://, ftp://, gopher://, etc.) before calling urlopen.
  - If the base URL is configurable per user/tenant, enforce an allowlist of approved LLM provider hostnames.
  - Consider migrating to the 'requests' library with timeout and allow_redirects=False, combined with the same scheme/host validation.
  - Add automated tests covering malicious URL schemes and internal/metadata IP targets to prevent regressions.
