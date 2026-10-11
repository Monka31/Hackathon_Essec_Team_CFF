"""Tests actifs NON DESTRUCTIFS, uniquement sur une cible dont l'utilisateur est propriétaire
et qu'il autorise explicitement (consentement renforcé dans l'interface).

Principes : aucune exploitation, aucune écriture, aucun brute force, aucun vol de données.
On envoie quelques requêtes GET avec des marqueurs inoffensifs et on lit la réponse pour
détecter des défauts classiques (reflet d'entrée, open redirect, CORS trop permissif, erreurs
bavardes). Toutes les URL passent par la validation SSRF de core.net.
"""
from __future__ import annotations

import urllib.parse
import urllib.request
from typing import List

from ..core.models import Evidence, Finding
from ..core.net import check_public_url, fetch

NAME = "active_probe"
UA = "Syberia-active-probe"
MARKER = "syberia7xq9z"
REDIRECT_PARAMS = ["next", "url", "redirect", "return", "returnTo", "dest", "destination", "continue"]
MAX_SECONDS = 25


def _f(title, severity, url, description, cwe="", fix=None, rule="", raw=None) -> Finding:
    return Finding(category="web", title=title, severity=severity, file=url, line=None,
                   description=description, cwe=[cwe] if cwe else [], fix_hint=fix, confidence="moyenne",
                   evidence=[Evidence(source=NAME, rule_id=rule or title, raw=raw or {})])


def _with_query(url: str, params: dict) -> str:
    p = urllib.parse.urlparse(url)
    q = dict(urllib.parse.parse_qsl(p.query))
    q.update(params)
    return urllib.parse.urlunparse(p._replace(query=urllib.parse.urlencode(q)))


def scan_url(url: str, timeout: int = 12) -> List[Finding]:
    check_public_url(url)
    out: List[Finding] = []

    # 1. Reflet d'entrée non encodé (possible XSS réfléchi). Marqueur inoffensif, aucun script exécuté.
    try:
        value = MARKER + "<x>"
        probe = _with_query(url, {"q": value})
        body = fetch(probe, timeout=timeout).body.decode("utf-8", "replace")
        if (MARKER + "<") in body:
            out.append(_f("Input reflected without encoding (possible reflected XSS)", "medium", probe,
                          "A unique harmless marker sent in a query parameter came back in the page without HTML-encoding "
                          "(the '<' was not turned into &lt;). If user input reaches the HTML like this, an attacker could "
                          "inject a script (reflected XSS). This is a safe detection, not an exploit.",
                          "CWE-79",
                          "Escape or HTML-encode user input before inserting it into the page, or rely on a framework that "
                          "auto-escapes, and add a Content-Security-Policy as defense in depth.",
                          rule="reflected-input", raw={"param": "q"}))
    except Exception:
        pass

    # 2. Open redirect. Valeur externe inoffensive, on ne suit PAS la redirection.
    for param in REDIRECT_PARAMS:
        try:
            probe = _with_query(url, {param: "https://example.com/syberia"})
            r = fetch(probe, timeout=timeout, follow_redirects=False)
            loc = r.headers.get("location", "")
            if r.status in (301, 302, 303, 307, 308) and "example.com" in loc:
                out.append(_f("Open redirect", "medium", probe,
                              f"The '{param}' parameter sends the user to an arbitrary external site "
                              f"(Location: {loc[:120]}). Attackers use this to craft convincing phishing links that start "
                              "on your trusted domain before bouncing elsewhere.",
                              "CWE-601",
                              "Only redirect to a fixed allowlist of internal paths; reject absolute external URLs.",
                              rule="open-redirect", raw={"param": param, "location": loc[:200]}))
                break
        except Exception:
            pass

    # 3. CORS trop permissif. Requête avec un Origin inoffensif, lecture seule.
    try:
        check_public_url(url)
        req = urllib.request.Request(url, headers={"User-Agent": UA, "Origin": "https://syberia-probe.example"})
        resp = urllib.request.urlopen(req, timeout=timeout)
        h = {k.lower(): v for k, v in resp.headers.items()} if resp.headers else {}
        acao = h.get("access-control-allow-origin", "")
        creds = h.get("access-control-allow-credentials", "").lower()
        if acao == "https://syberia-probe.example" and creds == "true":
            out.append(_f("CORS reflects any origin with credentials", "high", url,
                          "The server echoed an arbitrary Origin and allows credentials. Any website could then read this "
                          "app's authenticated responses on behalf of a logged-in user.",
                          "CWE-942",
                          "Allow only a fixed list of trusted origins; never reflect the request Origin together with "
                          "Access-Control-Allow-Credentials: true.",
                          rule="cors-misconfig", raw={"acao": acao, "credentials": creds}))
    except Exception:
        pass

    # 4. Erreurs bavardes. On demande une page inexistante et on cherche une stack trace.
    try:
        probe = url.rstrip("/") + "/syberia-notfound-" + MARKER
        body = fetch(probe, timeout=timeout).body.decode("utf-8", "replace")[:20000]
        signals = ["Traceback (most recent call last)", "Werkzeug Debugger", '.py", line', "java.lang.",
                   "SQLSTATE", "ORA-00", "Microsoft .NET", "NoMethodError", "stack trace"]
        hit = next((s for s in signals if s in body), None)
        if hit:
            out.append(_f("Verbose error / stack trace exposed", "medium", probe,
                          "An invalid request returned internal error details (stack trace or debug output). This leaks "
                          "file paths, libraries and internal logic that help an attacker.",
                          "CWE-209",
                          "Turn off debug mode in production and return a generic error page; keep details in server logs only.",
                          rule="verbose-error", raw={"signal": hit}))
    except Exception:
        pass

    return out
