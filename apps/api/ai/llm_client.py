"""Abstraction LLM minimaliste : Anthropic Claude / OpenAI / stub fallback.

Sélection automatique selon les variables d'environnement :
  ANTHROPIC_API_KEY  → claude-* (par défaut claude-haiku-4-5)
  OPENAI_API_KEY     → gpt-* (par défaut gpt-4o-mini)
  rien               → stub déterministe (génère une réponse synthétique)

Le stub permet aux tests + démos sans clé. Toutes les routes restent fonctionnelles.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Any

import httpx

DEFAULT_TIMEOUT = 30.0


@dataclass
class LlmResponse:
    text: str
    model: str
    provider: str
    usage: dict[str, int]
    raw: dict[str, Any] | None = None


def _stub_response(prompt: str, system: str | None) -> LlmResponse:
    """Réponse synthétique pour les environnements sans clé API.

    Renvoie un JSON parseable de manière déterministe pour ne pas casser
    les flows downstream (triage, rule-gen) qui attendent un format précis.
    """
    summary = (prompt[:200] + "...") if len(prompt) > 200 else prompt
    out = {
        "verdict": "needs_review",
        "confidence": 0.4,
        "summary": f"[STUB] no LLM key configured. Prompt echo: {summary}",
        "recommended_actions": [
            "Configure ANTHROPIC_API_KEY or OPENAI_API_KEY for real analysis",
            "Verify event source and correlate with TI feeds",
        ],
        "tags": ["stub", "no-llm-key"],
    }
    return LlmResponse(
        text=json.dumps(out, indent=2),
        model="stub",
        provider="stub",
        usage={"input_tokens": 0, "output_tokens": 0},
        raw={"stub": True},
    )


def _call_anthropic(
    prompt: str, system: str | None, model: str, max_tokens: int, api_key: str
) -> LlmResponse:
    body: dict[str, Any] = {
        "model": model,
        "max_tokens": max_tokens,
        "messages": [{"role": "user", "content": prompt}],
    }
    if system:
        body["system"] = system
    headers = {
        "x-api-key": api_key,
        "anthropic-version": "2023-06-01",
        "content-type": "application/json",
    }
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as c:
        r = c.post("https://api.anthropic.com/v1/messages", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    return LlmResponse(
        text=text,
        model=data.get("model", model),
        provider="anthropic",
        usage={
            "input_tokens": data.get("usage", {}).get("input_tokens", 0),
            "output_tokens": data.get("usage", {}).get("output_tokens", 0),
        },
        raw=data,
    )


def _call_openai(
    prompt: str, system: str | None, model: str, max_tokens: int, api_key: str
) -> LlmResponse:
    msgs: list[dict[str, str]] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    body = {"model": model, "messages": msgs, "max_tokens": max_tokens}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    with httpx.Client(timeout=DEFAULT_TIMEOUT) as c:
        r = c.post("https://api.openai.com/v1/chat/completions", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
    text = data["choices"][0]["message"]["content"]
    u = data.get("usage", {})
    return LlmResponse(
        text=text,
        model=data.get("model", model),
        provider="openai",
        usage={
            "input_tokens": u.get("prompt_tokens", 0),
            "output_tokens": u.get("completion_tokens", 0),
        },
        raw=data,
    )


def call_llm(
    prompt: str,
    system: str | None = None,
    max_tokens: int = 1024,
    prefer: str | None = None,
) -> LlmResponse:
    """Call LLM. `prefer` peut forcer 'anthropic', 'openai', ou 'stub'."""
    anth_key = os.environ.get("ANTHROPIC_API_KEY")
    oai_key = os.environ.get("OPENAI_API_KEY")

    if prefer == "stub":
        return _stub_response(prompt, system)

    chosen = prefer
    if chosen is None:
        chosen = "anthropic" if anth_key else ("openai" if oai_key else "stub")

    if chosen == "anthropic" and anth_key:
        model = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        return _call_anthropic(prompt, system, model, max_tokens, anth_key)
    if chosen == "openai" and oai_key:
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        return _call_openai(prompt, system, model, max_tokens, oai_key)

    return _stub_response(prompt, system)


def llm_status() -> dict[str, Any]:
    return {
        "anthropic_available": bool(os.environ.get("ANTHROPIC_API_KEY")),
        "openai_available": bool(os.environ.get("OPENAI_API_KEY")),
        "default_provider": (
            "anthropic" if os.environ.get("ANTHROPIC_API_KEY")
            else "openai" if os.environ.get("OPENAI_API_KEY")
            else "stub"
        ),
        "anthropic_model": os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001"),
        "openai_model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
    }


def parse_json_response(text: str) -> dict[str, Any] | None:
    """Best-effort JSON extraction d'une réponse LLM.

    Beaucoup de modèles enrobent le JSON dans ```json ... ``` ou ajoutent du préambule.
    On essaie : (1) parse direct, (2) extraction du premier bloc { ... } équilibré.
    """
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    start = text.find("{")
    if start == -1:
        return None
    depth = 0
    in_str = False
    esc = False
    for i in range(start, len(text)):
        ch = text[i]
        if esc:
            esc = False
            continue
        if ch == "\\":
            esc = True
            continue
        if ch == '"':
            in_str = not in_str
            continue
        if in_str:
            continue
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                try:
                    return json.loads(text[start : i + 1])
                except json.JSONDecodeError:
                    return None
    return None
