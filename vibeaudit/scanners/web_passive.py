"""Passive tests of the online app: fast, safe, no quota.

We only make normal GET requests, like a visitor: no attack payload is ever sent.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from http.cookies import SimpleCookie
from typing import List, Optional

from ..core.models import Evidence, Finding, FindingList
from ..core.net import Response, fetch
from .base import ScannerError

NAME = "web_passive"

SECURITY_HEADERS = [
    ("content-security-policy", "medium", "No Content-Security-Policy",
     "Without a CSP, an injected script (XSS) can run freely in the page.", "CWE-693"),
    ("strict-transport-security", "medium", "No Strict-Transport-Security (HSTS)",
     "The browser can be forced back to unencrypted HTTP (attack on public Wi-Fi).", "CWE-319"),
    ("x-content-type-options", "low", "No X-Content-Type-Options",
     "The browser may interpret a file as a script.", "CWE-693"),
    ("referrer-policy", "low", "No Referrer-Policy",
     "Full URLs (with possible tokens) can leak to third-party sites.", "CWE-200"),
]

# Files that must never be publicly reachable, with a signature to avoid false positives
EXPOSED_FILES = [
    ("/.env", re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M), "Publicly accessible .env file"),
    ("/.env.local", re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M), "Publicly accessible .env.local file"),
    ("/.env.production", re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M), "Publicly accessible .env.production file"),
    ("/.git/HEAD", re.compile(r"^ref: refs/", re.M), "Publicly accessible .git folder (source code downloadable)"),
    ("/.git/config", re.compile(r"\[core\]"), "Publicly accessible .git/config file"),
]

SECRET_PATTERNS = [
    ("Stripe secret key", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"), "critical"),
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "critical"),
    ("OpenAI key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}"), "critical"),
    ("Anthropic key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium"),
]
JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
SCRIPT_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.I)


def _f(title, severity, url, description, cwe="", fix=None, rule="", raw=None, snippet=None) -> Finding:
    return Finding(
        category="web", title=title, severity=severity, file=url, line=None, snippet=snippet,
        description=description, cwe=[cwe] if cwe else [], fix_hint=fix,
        evidence=[Evidence(source=NAME, rule_id=rule or title, raw=raw or {})],
    )


def _jwt_role(token: str) -> Optional[str]:
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("role")
    except Exception:
        return None


def _check_https(url: str, home: Response) -> List[Finding]:
    out = []
    p = urllib.parse.urlparse(home.url)
    if p.scheme != "https":
        out.append(_f("The site is not served over HTTPS", "high", home.url,
                      "Traffic (passwords, customer data) travels in clear text.", "CWE-319",
                      "Enable HTTPS (free certificate on most hosts) and redirect HTTP to HTTPS.",
                      "no-https"))
        return out
    try:
        r = fetch("http://" + p.netloc + "/", follow_redirects=False, timeout=10)
        loc = r.headers.get("location", "")
        if r.status < 300 or r.status >= 400 or not loc.startswith("https://"):
            out.append(_f("HTTP does not redirect to HTTPS", "medium", "http://" + p.netloc,
                          f"The HTTP version answers (status {r.status}) without redirecting to HTTPS.", "CWE-319",
                          "Configure a 301 redirect from HTTP to HTTPS.", "no-https-redirect",
                          {"status": r.status, "location": loc}))
    except Exception:
        pass  # port 80 closed: that is fine
    return out


def _check_headers(home: Response) -> List[Finding]:
    out = []
    h = home.headers
    for name, sev, title, desc, cwe in SECURITY_HEADERS:
        if name == "strict-transport-security" and not home.url.startswith("https://"):
            continue
        if name not in h:
            out.append(_f(title, sev, home.url, desc, cwe,
                          f"Add the HTTP header '{name}' in your host or framework config.",
                          f"missing-{name}", {"present_headers": sorted(h)}))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(_f("The site can be shown inside an iframe (clickjacking)", "low", home.url,
                      "A malicious site can overlay your app and trick clicks.", "CWE-1021",
                      "Add 'X-Frame-Options: DENY' or 'Content-Security-Policy: frame-ancestors 'none''.",
                      "missing-frame-protection"))
    server = h.get("server", "") + " " + h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server):
        out.append(_f("Server version disclosed", "low", home.url,
                      f"The server advertises its version ({server.strip()}), helping an attacker target known flaws.",
                      "CWE-200", "Hide the Server and X-Powered-By headers.", "server-version", {"server": server.strip()}))
    for header in home.raw_headers:
        parsed = SimpleCookie()
        try:
            parsed.load(header)
        except Exception:
            continue
        for name, morsel in parsed.items():
            low_name = name.lower()
            # Public preference/consent cookies do not protect an authenticated session.
            if any(word in low_name for word in ("locale", "language", "theme", "consent", "preference")):
                continue
            # Only score cookies whose names indicate authentication/session material.
            sensitive = any(word in low_name for word in ("session", "auth", "token", "jwt", "access", "refresh", "remember"))
            sensitive = sensitive or low_name in {"sid", "ssid"} or low_name.endswith(("_sid", "-sid"))
            if not sensitive:
                continue
            missing = [attr for attr, present in (("Secure", bool(morsel["secure"])),
                                                   ("HttpOnly", bool(morsel["httponly"])),
                                                   ("SameSite", bool(morsel["samesite"]))) if not present]
            if missing:
                out.append(_f(f"Authentication cookie '{name}' missing {' and '.join(missing)}", "medium", home.url,
                              "This cookie appears to carry session or authentication state and is missing security flags.",
                              "CWE-614", "Set Secure, HttpOnly and an appropriate SameSite policy on this authentication cookie.",
                              "auth-cookie-flags", {"cookie": name, "missing": missing}))
    return out


def _check_exposed(base: str) -> List[Finding]:
    def probe(item):
        path, sig, title = item
        try:
            r = fetch(base + path, follow_redirects=False, timeout=10, max_bytes=20000)
        except Exception:
            return None
        if r.status == 200 and sig.search(r.text) and "<html" not in r.text[:500].lower():
            return _f(title, "critical", base + path,
                      "This file is downloadable by anyone. It often contains passwords or keys.",
                      "CWE-538", "Block access to this file on the server, then rotate any keys it contained.",
                      "exposed-file", {"path": path, "status": r.status, "size": len(r.body)})
        return None

    with ThreadPoolExecutor(max_workers=5) as pool:
        return [f for f in pool.map(probe, EXPOSED_FILES) if f]


def _check_js_secrets(home: Response) -> FindingList:
    """Look for keys in the HTML and JavaScript files of the site (what every visitor downloads)."""
    p = urllib.parse.urlparse(home.url)
    sources = [(home.url, home.text)]
    scripts = []
    for src in SCRIPT_RE.findall(home.text):
        full = urllib.parse.urljoin(home.url, src)
        if urllib.parse.urlparse(full).netloc == p.netloc:
            scripts.append(full)
    for s in list(dict.fromkeys(scripts))[:20]:
        try:
            r = fetch(s, timeout=15)
            if r.status == 200:
                sources.append((s, r.text))
        except Exception:
            continue

    out, seen = [], set()
    public_supabase_key = False
    for src_url, text in sources:
        for label, rx, sev in SECRET_PATTERNS:
            for m in rx.finditer(text):
                if m.group(0) in seen:
                    continue
                seen.add(m.group(0))
                out.append(_f(f"{label} visible in the site code", sev, src_url,
                              "This key is sent to every visitor's browser: anyone can retrieve it.",
                              "CWE-798", "Revoke the key, generate a new one, and use it server-side only.",
                              "js-secret", {"secret": m.group(0), "type": label}))
        for m in JWT_RE.finditer(text):
            tok = m.group(0)
            if tok in seen:
                continue
            seen.add(tok)
            role = _jwt_role(tok)
            if role == "service_role":
                out.append(_f("Supabase service_role key visible in the site code", "critical", src_url,
                              "This key bypasses all security rules (RLS): any visitor can read, change or delete "
                              "the whole database.",
                              "CWE-798", "Rotate the key in Supabase (Settings > API), and use it server-side only.",
                              "supabase-service-role", {"secret": tok, "role": role}))
            elif role == "anon":
                # Supabase anon/publishable keys are designed to ship to browsers.
                # Their presence alone does not demonstrate an access-control failure.
                public_supabase_key = True
    note = ("Public Supabase anon key observed; this is expected in browser code and was not scored as a finding. "
            "URL-only checks cannot determine whether database tables have correct RLS policies."
            if public_supabase_key else "")
    return FindingList(out, note=note)


def scan_url(url: str) -> List[Finding]:
    try:
        home = fetch(url, timeout=20)
    except Exception as e:
        raise ScannerError(f"site unreachable: {e}")
    if home.status >= 500:
        raise ScannerError(f"the site answers with an error ({home.status})")
    p = urllib.parse.urlparse(home.url)
    base = f"{p.scheme}://{p.netloc}"
    findings = _check_https(url, home) + _check_headers(home)
    findings += _check_exposed(base)
    js_findings = _check_js_secrets(home)
    findings += js_findings
    return FindingList(findings, note=js_findings.note)
