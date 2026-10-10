"""Accès réseau sûr : on ne laisse jamais la plateforme appeler une adresse interne (protection SSRF).

Sur EC2, une URL comme http://169.254.169.254/ donnerait accès aux identifiants du serveur :
toute URL fournie par un utilisateur passe donc par check_public_url().
"""
from __future__ import annotations

import ipaddress
import os
import re
import socket
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from typing import Dict, Optional

USER_AGENT = "vibeaudit/0.2 (audit de securite autorise par le proprietaire)"
MAX_BYTES = 3_000_000


class UnsafeURL(ValueError):
    pass


def check_public_url(url: str) -> urllib.parse.ParseResult:
    p = urllib.parse.urlparse(url.strip())
    if p.scheme not in ("http", "https") or not p.hostname:
        raise UnsafeURL("l'URL doit commencer par http:// ou https://")
    if p.username or p.password:
        raise UnsafeURL("pas d'identifiants dans l'URL")
    if p.port and p.port not in (80, 443, 8080, 8443):
        raise UnsafeURL("port non autorisé")
    try:
        infos = socket.getaddrinfo(p.hostname, p.port or (443 if p.scheme == "https" else 80))
    except socket.gaierror:
        raise UnsafeURL(f"domaine introuvable : {p.hostname}")
    for info in infos:
        if ipaddress.ip_address(info[4][0]).is_link_local:
            raise UnsafeURL("adresse interne refusée")  # métadonnées cloud (169.254.169.254) : toujours bloqué
    if os.getenv("ALLOW_PRIVATE_URLS") == "1":  # tests en local uniquement, jamais sur le serveur
        return p
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if not ip.is_global:
            raise UnsafeURL("adresse interne ou privée refusée")
    return p


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        check_public_url(newurl)  # chaque redirection est revérifiée
        return super().redirect_request(req, fp, code, msg, headers, newurl)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args, **kwargs):
        return None


@dataclass
class Response:
    url: str
    status: int
    headers: Dict[str, str] = field(default_factory=dict)
    raw_headers: list = field(default_factory=list)
    body: bytes = b""

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


def fetch(url: str, timeout: int = 15, follow_redirects: bool = True, max_bytes: int = MAX_BYTES) -> Response:
    check_public_url(url)
    opener = urllib.request.build_opener(_SafeRedirect() if follow_redirects else _NoRedirect())
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Accept": "*/*"})
    try:
        resp = opener.open(req, timeout=timeout)
    except urllib.error.HTTPError as e:
        resp = e
    body = resp.read(max_bytes) if hasattr(resp, "read") else b""
    headers = {k.lower(): v for k, v in resp.headers.items()} if resp.headers else {}
    raw = resp.headers.get_all("Set-Cookie") if resp.headers else []
    return Response(url=resp.geturl() if hasattr(resp, "geturl") else url, status=resp.status if hasattr(resp, "status") else resp.code,
                    headers=headers, raw_headers=raw or [], body=body)


GITHUB_RE = re.compile(r"^https://github\.com/([A-Za-z0-9_.-]{1,100})/([A-Za-z0-9_.-]{1,100}?)(?:\.git)?/?$")


def parse_github_url(url: str) -> Optional[tuple]:
    """Renvoie (owner, repo) ou None. Format strict : évite toute injection d'option dans git."""
    m = GITHUB_RE.match(url.strip())
    if not m:
        return None
    owner, repo = m.group(1), m.group(2)
    if owner.startswith("-") or repo.startswith("-") or ".." in owner + repo:
        return None
    return owner, repo
