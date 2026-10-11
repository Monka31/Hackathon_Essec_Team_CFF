"""Appel au LLM, interchangeable (choix I) : Bedrock par défaut, API Claude directe en secours.

LLM_PROVIDER=bedrock    -> Claude via Amazon Bedrock (AWS_REGION, BEDROCK_MODEL_ID)
LLM_PROVIDER=anthropic  -> API Claude directe (ANTHROPIC_API_KEY, ANTHROPIC_MODEL)
LLM_PROVIDER=fake       -> réponses factices, pour travailler sur l'interface sans consommer
LLM_PROVIDER=off        -> pas d'IA
"""
from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from typing import Optional


TOOL_NAME = "enregistrer_analyse"


class LLMUnavailable(Exception):
    """Pas d'IA possible (pas configurée, identifiants absents ou expirés)."""


class LLMError(Exception):
    pass


def provider() -> str:
    return os.getenv("LLM_PROVIDER", "bedrock").lower()


def _bedrock(system: str, prompt: str, max_tokens: int, schema: Optional[dict] = None, model: Optional[str] = None):
    try:
        import boto3
        from botocore.config import Config
        from botocore.exceptions import ClientError, NoCredentialsError
    except ImportError:
        raise LLMUnavailable("boto3 n'est pas installé (pip install -r requirements.txt)")
    region = os.getenv("AWS_REGION") or os.getenv("AWS_DEFAULT_REGION") or "us-west-2"
    model = model or os.getenv("BEDROCK_MODEL_ID", "us.anthropic.claude-sonnet-5")
    client = boto3.client("bedrock-runtime", region_name=region,
                          config=Config(connect_timeout=10, read_timeout=180, retries={"max_attempts": 2}))
    kwargs = dict(
        modelId=model,
        system=[{"text": system}],
        messages=[{"role": "user", "content": [{"text": prompt}]}],
        inferenceConfig={"maxTokens": max_tokens, "temperature": 0},
    )
    if schema:
        # Sortie structurée : on force le modèle à "appeler un outil" dont les paramètres suivent notre schéma.
        # Bedrock renvoie alors un objet déjà décodé, plus de JSON coupé ou mal formé.
        kwargs["toolConfig"] = {
            "tools": [{"toolSpec": {"name": TOOL_NAME, "description": "Enregistre l'analyse structurée.",
                                    "inputSchema": {"json": schema}}}],
            "toolChoice": {"tool": {"name": TOOL_NAME}},
        }
    try:
        try:
            resp = client.converse(**kwargs)
        except ClientError as e:
            if "temperature" in str(e).lower():  # certains modèles refusent ce paramètre
                kwargs["inferenceConfig"].pop("temperature")
                resp = client.converse(**kwargs)
            else:
                raise
    except NoCredentialsError:
        raise LLMUnavailable("identifiants AWS absents : recoller les 3 lignes 'export' de Workshop Studio dans ce Terminal")
    except ClientError as e:
        code = e.response.get("Error", {}).get("Code", "")
        if code in ("ExpiredTokenException", "ExpiredToken", "UnrecognizedClientException"):
            raise LLMUnavailable("identifiants AWS expirés : recoller les 3 lignes 'export' de Workshop Studio")
        if code == "AccessDeniedException":
            raise LLMUnavailable(f"accès refusé au modèle {model} (vérifier Bedrock > Model access)")
        raise LLMError(f"Bedrock : {code} {str(e)[:200]}")
    except Exception as e:
        if "endpoint" in str(e).lower() or "connect" in str(e).lower():
            raise LLMUnavailable("Bedrock injoignable (réseau ? le Wi-Fi de l'école bloque Bedrock)")
        raise LLMError(f"Bedrock : {type(e).__name__} {str(e)[:200]}")

    blocks = (resp.get("output", {}).get("message", {}) or {}).get("content", []) or []
    if schema:
        for b in blocks:
            if isinstance(b, dict) and "toolUse" in b:
                return b["toolUse"].get("input") or {}
        if resp.get("stopReason") == "max_tokens":
            raise LLMError("réponse coupée (limite de longueur atteinte)")
    # Plusieurs blocs possibles (ex : un bloc de raisonnement avant le texte) : on garde le texte
    text = "".join(b.get("text", "") for b in blocks if isinstance(b, dict))
    if not text:
        raise LLMError(f"réponse Bedrock sans texte (blocs reçus : {[list(b) for b in blocks][:3]})")
    return text


def _anthropic(system: str, prompt: str, max_tokens: int, schema: Optional[dict] = None):
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key:
        raise LLMUnavailable("ANTHROPIC_API_KEY absent du .env")
    payload = {
        "model": os.getenv("ANTHROPIC_MODEL", "claude-sonnet-5-5"),
        "max_tokens": max_tokens,
        "system": system,
        "messages": [{"role": "user", "content": prompt}],
    }
    if schema:
        payload["tools"] = [{"name": TOOL_NAME, "description": "Enregistre l'analyse structurée.", "input_schema": schema}]
        payload["tool_choice"] = {"type": "tool", "name": TOOL_NAME}
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages", data=json.dumps(payload).encode(), method="POST",
        headers={"x-api-key": key, "anthropic-version": "2023-06-01", "content-type": "application/json"},
    )
    if req.full_url.split(":", 1)[0].lower() != "https":
        raise LLMError("URL API Claude invalide : seul https est autorisé")
    try:
        with urllib.request.urlopen(req, timeout=180) as r:  # nosec B310 - schéma validé ci-dessus (https uniquement)
            data = json.loads(r.read().decode())
    except urllib.error.HTTPError as e:
        if e.code in (401, 403):
            raise LLMUnavailable("clé API Claude refusée")
        raise LLMError(f"API Claude : HTTP {e.code} {e.read().decode(errors='replace')[:200]}")
    except urllib.error.URLError as e:
        raise LLMUnavailable(f"API Claude injoignable : {e.reason}")
    if schema:
        for b in data.get("content", []):
            if b.get("type") == "tool_use":
                return b.get("input") or {}
    return "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")


def _fake(system: str, prompt: str, max_tokens: int, schema: Optional[dict] = None):
    out = None
    if '"summary"' in system or (schema and "summary" in schema.get("properties", {})):
        out = ({"summary": "Résumé factice (LLM_PROVIDER=fake).", "priorities": ["Priorité 1", "Priorité 2", "Priorité 3"]})
    else:
        out = ({
        "explanations": {lvl: f"Explication factice niveau {lvl}." for lvl in ("debutant", "intermediaire", "avance", "expert")},
        "verdict": "confirmed", "confidence": "moyenne", "confidence_reason": "réponse factice",
        "attack_scenario": "Scénario factice.", "fix_steps": ["Étape 1", "Étape 2"],
        "prompt_injection_detected": False, "injection_note": "",
    })
    return out if schema else json.dumps(out)


def complete(system: str, prompt: str, max_tokens: int = 1800, schema: Optional[dict] = None,
             model: Optional[str] = None):
    """Texte libre, ou dict si un schéma est donné (sortie structurée forcée).
    model : identifiant de modèle Bedrock à utiliser à la place de celui par défaut (ex : modèle plus rapide)."""
    p = provider()
    if p in ("off", "none", ""):
        raise LLMUnavailable("IA désactivée (LLM_PROVIDER=off)")
    if p == "bedrock":
        return _bedrock(system, prompt, max_tokens, schema, model)
    fn = {"anthropic": _anthropic, "fake": _fake}.get(p)
    if not fn:
        raise LLMUnavailable(f"LLM_PROVIDER inconnu : {p}")
    return fn(system, prompt, max_tokens, schema)


def parse_json(text: str) -> Optional[dict]:
    """Extrait le premier objet JSON de la réponse (le modèle peut ajouter du texte autour)."""
    if not text:
        return None
    text = re.sub(r"^```(?:json)?|```$", "", text.strip(), flags=re.M).strip()
    try:
        return json.loads(text, strict=False)  # strict=False : tolère les retours à la ligne dans les textes
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    end = text.rfind("}")
    if start >= 0 and end > start:
        try:
            return json.loads(text[start:end + 1], strict=False)
        except json.JSONDecodeError:
            return None
    return None
