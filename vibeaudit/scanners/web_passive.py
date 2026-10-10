"""Tests passifs de l'appli en ligne : rapides, sans danger, sans quota.

On ne fait que des requêtes GET normales, comme un visiteur : aucune attaque n'est envoyée.
"""
from __future__ import annotations

import base64
import json
import re
import urllib.parse
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional

from ..core.models import Evidence, Finding
from ..core.net import Response, fetch
from .base import ScannerError

NAME = "web_passive"

SECURITY_HEADERS = [
    ("content-security-policy", "medium", "Pas de Content-Security-Policy",
     "Sans CSP, un script injecté (XSS) peut s'exécuter librement dans la page.", "CWE-693"),
    ("strict-transport-security", "medium", "Pas de Strict-Transport-Security (HSTS)",
     "Le navigateur peut être forcé à repasser en HTTP non chiffré (attaque sur un Wi-Fi public).", "CWE-319"),
    ("x-content-type-options", "low", "Pas de X-Content-Type-Options",
     "Le navigateur peut interpréter un fichier comme un script.", "CWE-693"),
    ("referrer-policy", "low", "Pas de Referrer-Policy",
     "Les URL complètes (avec d'éventuels jetons) peuvent fuiter vers les sites tiers.", "CWE-200"),
]

# Fichiers qui ne doivent jamais être accessibles publiquement, avec une signature pour éviter les faux positifs
EXPOSED_FILES = [
    ("/.env", re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M), "Fichier .env accessible publiquement"),
    ("/.env.local", re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M), "Fichier .env.local accessible publiquement"),
    ("/.env.production", re.compile(r"^[A-Z0-9_]{2,}\s*=", re.M), "Fichier .env.production accessible publiquement"),
    ("/.git/HEAD", re.compile(r"^ref: refs/", re.M), "Dossier .git accessible publiquement (code source téléchargeable)"),
    ("/.git/config", re.compile(r"\[core\]"), "Fichier .git/config accessible publiquement"),
]

SECRET_PATTERNS = [
    ("Clé secrète Stripe", re.compile(r"\bsk_live_[A-Za-z0-9]{16,}"), "critical"),
    ("Clé d'accès AWS", re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "critical"),
    ("Jeton GitHub", re.compile(r"\bgh[pousr]_[A-Za-z0-9]{30,}"), "critical"),
    ("Clé OpenAI", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{30,}"), "critical"),
    ("Clé Anthropic", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{30,}"), "critical"),
    ("Clé API Google", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "medium"),  # souvent publique mais à restreindre
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
        out.append(_f("Le site n'est pas servi en HTTPS", "high", home.url,
                      "Les échanges (mots de passe, données clients) circulent en clair.", "CWE-319",
                      "Activer HTTPS (certificat gratuit chez la plupart des hébergeurs) et rediriger HTTP vers HTTPS.",
                      "no-https"))
        return out
    try:
        r = fetch("http://" + p.netloc + "/", follow_redirects=False, timeout=10)
        loc = r.headers.get("location", "")
        if r.status < 300 or r.status >= 400 or not loc.startswith("https://"):
            out.append(_f("HTTP ne redirige pas vers HTTPS", "medium", "http://" + p.netloc,
                          f"La version HTTP répond (code {r.status}) sans rediriger vers HTTPS.", "CWE-319",
                          "Configurer une redirection 301 de HTTP vers HTTPS.", "no-https-redirect",
                          {"status": r.status, "location": loc}))
    except Exception:
        pass  # port 80 fermé : c'est très bien
    return out


def _check_headers(home: Response) -> List[Finding]:
    out = []
    h = home.headers
    for name, sev, title, desc, cwe in SECURITY_HEADERS:
        if name == "strict-transport-security" and not home.url.startswith("https://"):
            continue
        if name not in h:
            out.append(_f(title, sev, home.url, desc, cwe, f"Ajouter l'en-tête HTTP '{name}' dans la config de l'hébergeur ou du framework.",
                          f"missing-{name}", {"present_headers": sorted(h)}))
    if "x-frame-options" not in h and "frame-ancestors" not in h.get("content-security-policy", ""):
        out.append(_f("Le site peut être affiché dans une iframe (clickjacking)", "low", home.url,
                      "Un site malveillant peut afficher votre appli en transparence et piéger les clics.", "CWE-1021",
                      "Ajouter 'X-Frame-Options: DENY' ou 'Content-Security-Policy: frame-ancestors 'none''.", "missing-frame-protection"))
    server = h.get("server", "") + " " + h.get("x-powered-by", "")
    if re.search(r"\d+\.\d+", server):
        out.append(_f("Version du serveur affichée", "low", home.url,
                      f"Le serveur annonce sa version ({server.strip()}), ce qui aide un attaquant à cibler les failles connues.",
                      "CWE-200", "Masquer les en-têtes Server et X-Powered-By.", "server-version", {"server": server.strip()}))
    for cookie in home.raw_headers:
        low = cookie.lower()
        name = cookie.split("=", 1)[0]
        missing = [a for a in ("secure", "httponly") if a not in low]
        if missing:
            out.append(_f(f"Cookie '{name}' sans {' ni '.join(missing)}", "low", home.url,
                          "Un cookie sans Secure peut partir en clair, sans HttpOnly il est lisible par un script injecté.",
                          "CWE-614", "Ajouter les attributs Secure, HttpOnly et SameSite au cookie.", "cookie-flags",
                          {"cookie": name, "missing": missing}))
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
                      "Ce fichier est téléchargeable par n'importe qui. Il contient souvent des mots de passe ou des clés.",
                      "CWE-538", "Bloquer l'accès à ce fichier sur le serveur, puis changer toutes les clés qu'il contenait.",
                      "exposed-file", {"path": path, "status": r.status, "size": len(r.body)})
        return None

    with ThreadPoolExecutor(max_workers=5) as pool:
        return [f for f in pool.map(probe, EXPOSED_FILES) if f]


def _check_js_secrets(home: Response) -> List[Finding]:
    """Cherche des clés dans le HTML et les fichiers JavaScript du site (ce que tout visiteur télécharge)."""
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
    for src_url, text in sources:
        for label, rx, sev in SECRET_PATTERNS:
            for m in rx.finditer(text):
                if m.group(0) in seen:
                    continue
                seen.add(m.group(0))
                out.append(_f(f"{label} visible dans le code du site", sev, src_url,
                              "Cette clé est envoyée au navigateur de chaque visiteur : n'importe qui peut la récupérer.",
                              "CWE-798", "Révoquer la clé, la régénérer, et ne l'utiliser que côté serveur.",
                              "js-secret", {"secret": m.group(0), "type": label}))
        for m in JWT_RE.finditer(text):
            tok = m.group(0)
            if tok in seen:
                continue
            seen.add(tok)
            role = _jwt_role(tok)
            if role == "service_role":
                out.append(_f("Clé Supabase service_role visible dans le code du site", "critical", src_url,
                              "Cette clé contourne toutes les règles de sécurité (RLS) : n'importe quel visiteur peut lire, "
                              "modifier ou supprimer toute la base de données.",
                              "CWE-798", "Révoquer la clé dans Supabase (Settings > API), et ne l'utiliser que côté serveur.",
                              "supabase-service-role", {"secret": tok, "role": role}))
            elif role == "anon":
                out.append(_f("Clé Supabase publique (anon) détectée", "low", src_url,
                              "C'est normal qu'elle soit visible, mais toute la sécurité repose alors sur les règles RLS "
                              "de chaque table : une table sans RLS est lisible par n'importe qui avec cette clé.",
                              "", "Vérifier que la RLS est activée sur toutes les tables (Supabase > Advisors > Security).",
                              "supabase-anon", {"secret": tok, "role": role}))
    return out


def scan_url(url: str) -> List[Finding]:
    try:
        home = fetch(url, timeout=20)
    except Exception as e:
        raise ScannerError(f"site injoignable : {e}")
    if home.status >= 500:
        raise ScannerError(f"le site répond en erreur ({home.status})")
    p = urllib.parse.urlparse(home.url)
    base = f"{p.scheme}://{p.netloc}"
    findings = _check_https(url, home) + _check_headers(home)
    findings += _check_exposed(base)
    findings += _check_js_secrets(home)
    return findings
