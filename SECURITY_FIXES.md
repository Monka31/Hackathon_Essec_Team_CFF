# Security fixes proposed by vibeaudit

This pull request was opened by vibeaudit. It only ADDS files (recommendations and
example migrations). Nothing in your existing code was changed and nothing was deployed.
Review each item below, apply what you agree with, then merge.

## Dynamic urllib use detected  (MEDIUM)
- Location: `vibeaudit/llm/client.py:113`
- Recommended fix:
  - Trace back where the Request object's URL/base_url is defined and confirm it is a developer-set constant or config value, not derived from untrusted/user input.
  - If the URL can be influenced externally, add an allowlist check on scheme (http/https only) and host (known LLM provider domains) before building the Request.
  - Reject or sanitize any file://, ftp://, or internal/metadata IP addresses (e.g. 169.254.169.254, localhost, private ranges) to prevent SSRF/file read.
  - Consider replacing urllib.request with the 'requests' library plus explicit scheme/host validation for clearer security controls.
  - Add a regression test that attempts a malicious scheme/URL and asserts the call is blocked.
