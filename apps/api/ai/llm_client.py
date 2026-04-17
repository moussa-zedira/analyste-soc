"""Abstraction LLM async durcie : multi-provider Anthropic/OpenAI + stub.

Apports vs version sync :
- httpx.AsyncClient (toutes les methodes async)
- retry exponentiel (3 tentatives, backoff 1s/2s/4s) sur 429/5xx/timeout
- respect du header `Retry-After` sur 429
- fallback automatique provider B si provider A echoue (429 ou erreur)
- cost tracking : insertion AiCostLog + agregation Redis journaliere

API publique :
- `await call(prompt, ...)` async (point d'entree principal)
- `call_llm(prompt, ...)` wrapper sync (compat existant : tests, modules sync)
- `parse_json_response(text)` extraction JSON best-effort
- `llm_status()` etat des providers
- `MODEL_PRICING` dict (USD per 1M tokens : input, output)
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

import httpx

logger = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 30.0
MAX_RETRIES = 3
BACKOFF_SCHEDULE = (1.0, 2.0, 4.0)  # secondes entre tentatives


# Pricing : USD per 1M tokens (input, output). Maintenir a jour.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    # Anthropic
    "claude-opus-4-7": (15.0, 75.0),
    "claude-opus-4-7-20250101": (15.0, 75.0),
    "claude-opus-4-5": (15.0, 75.0),
    "claude-sonnet-4-5": (3.0, 15.0),
    "claude-sonnet-4-5-20250929": (3.0, 15.0),
    "claude-haiku-4-5": (1.0, 5.0),
    "claude-haiku-4-5-20251001": (1.0, 5.0),
    "claude-3-5-sonnet-20241022": (3.0, 15.0),
    "claude-3-5-haiku-20241022": (0.80, 4.0),
    # OpenAI
    "gpt-4o": (5.0, 15.0),
    "gpt-4o-2024-11-20": (2.50, 10.0),
    "gpt-4o-mini": (0.15, 0.60),
    "gpt-4-turbo": (10.0, 30.0),
    "gpt-4": (30.0, 60.0),
    "o1": (15.0, 60.0),
    "o1-mini": (3.0, 12.0),
}


@dataclass
class LlmResponse:
    text: str
    model: str
    provider: str
    usage: dict[str, int]
    raw: dict[str, Any] | None = None
    latency_ms: int = 0
    cost_usd: float = 0.0


# ── Retry / classification ────────────────────────────────────────────


_RETRYABLE_STATUS = {429, 500, 502, 503, 504}


class _Retryable(Exception):
    """Erreur retentable : 429/5xx/timeout/connect."""

    def __init__(self, msg: str, retry_after: float | None = None, status: int | None = None):
        super().__init__(msg)
        self.retry_after = retry_after
        self.status = status


class _Fatal(Exception):
    """Erreur non retentable : 4xx (sauf 429), schema, etc."""

    def __init__(self, msg: str, status: int | None = None):
        super().__init__(msg)
        self.status = status


def _classify(exc: Exception) -> _Retryable | _Fatal:
    if isinstance(exc, httpx.HTTPStatusError):
        status = exc.response.status_code
        if status in _RETRYABLE_STATUS:
            ra = exc.response.headers.get("Retry-After") if exc.response is not None else None
            wait: float | None = None
            if ra:
                try:
                    wait = float(ra)
                except ValueError:
                    wait = None
            return _Retryable(f"HTTP {status}", retry_after=wait, status=status)
        return _Fatal(f"HTTP {status}: {exc.response.text[:200]}", status=status)
    if isinstance(exc, (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)):
        return _Retryable(f"network: {type(exc).__name__}: {exc}")
    return _Fatal(f"{type(exc).__name__}: {exc}")


# ── Pricing / cost log ───────────────────────────────────────────────


def _compute_cost(model: str, tokens_in: int, tokens_out: int) -> tuple[float, float, float]:
    """Retourne (cost_in, cost_out, total) en USD."""
    price_in, price_out = MODEL_PRICING.get(model, (0.0, 0.0))
    if (price_in, price_out) == (0.0, 0.0):
        # Fallback : essai sur prefix (ex: "gpt-4o-2024-xx-xx" -> "gpt-4o")
        for key, (pi, po) in MODEL_PRICING.items():
            if model.startswith(key):
                price_in, price_out = pi, po
                break
    c_in = (tokens_in / 1_000_000.0) * price_in
    c_out = (tokens_out / 1_000_000.0) * price_out
    return c_in, c_out, c_in + c_out


def _log_cost(
    *,
    provider: str,
    model: str,
    operation: str,
    tokens_in: int,
    tokens_out: int,
    latency_ms: int,
    success: bool,
    error_msg: str | None = None,
) -> None:
    """Insere une ligne AiCostLog + invalide/met a jour le cache Redis daily.

    Best-effort : aucune exception ne remonte (on ne casse pas l'appel LLM).
    """
    try:
        # Imports tardifs pour eviter les cycles
        from apps.api.db.session import SessionLocal
        from apps.api.models.ai_cost import AiCostLog

        c_in, c_out, total = _compute_cost(model, tokens_in, tokens_out)
        row = AiCostLog(
            id=str(uuid.uuid4()),
            ts=datetime.now(timezone.utc),
            provider=provider,
            model=model,
            operation=operation,
            tokens_in=tokens_in,
            tokens_out=tokens_out,
            cost_usd_in=c_in,
            cost_usd_out=c_out,
            cost_usd_total=total,
            latency_ms=latency_ms,
            success=success,
            error_msg=error_msg[:500] if error_msg else None,
        )
        db = SessionLocal()
        try:
            db.add(row)
            db.commit()
        finally:
            db.close()

        # Recalcul aggregation Redis (best-effort)
        _refresh_daily_cost_cache()
    except Exception as e:  # pragma: no cover (best-effort)
        logger.debug("ai_cost_log insert failed: %s", e)


def _refresh_daily_cost_cache(day: str | None = None) -> dict[str, Any] | None:
    """Recalcule l'agregation cout du jour en Redis (TTL 48h)."""
    try:
        from sqlalchemy import func

        from apps.api.cache import _get_redis
        from apps.api.db.session import SessionLocal
        from apps.api.models.ai_cost import AiCostLog

        if day is None:
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")

        db = SessionLocal()
        try:
            day_start = datetime.strptime(day, "%Y-%m-%d").replace(tzinfo=timezone.utc)
            day_end_iso = f"{day} 23:59:59"
            rows = (
                db.query(
                    AiCostLog.provider,
                    func.count(AiCostLog.id),
                    func.sum(AiCostLog.tokens_in),
                    func.sum(AiCostLog.tokens_out),
                    func.sum(AiCostLog.cost_usd_total),
                )
                .filter(AiCostLog.ts >= day_start)
                .filter(AiCostLog.ts < datetime.strptime(day_end_iso, "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc))
                .group_by(AiCostLog.provider)
                .all()
            )
        finally:
            db.close()

        agg: dict[str, Any] = {}
        total_usd = 0.0
        for provider, calls, t_in, t_out, cost in rows:
            agg[provider] = {
                "calls": int(calls or 0),
                "tokens_in": int(t_in or 0),
                "tokens_out": int(t_out or 0),
                "cost_usd": float(cost or 0.0),
            }
            total_usd += float(cost or 0.0)
        agg["total_usd"] = round(total_usd, 6)
        agg["day"] = day

        r = _get_redis()
        if r is not None:
            try:
                r.setex(f"ai:cost:daily:{day}", 48 * 3600, json.dumps(agg, default=str))
            except Exception:
                pass
        return agg
    except Exception as e:  # pragma: no cover
        logger.debug("daily cost cache refresh failed: %s", e)
        return None


# ── Stub ─────────────────────────────────────────────────────────────


def _stub_response(prompt: str, system: str | None) -> LlmResponse:
    """Reponse synthetique pour les environnements sans cle API."""
    summary = (prompt[:200] + "...") if len(prompt) > 200 else prompt
    out = {
        "verdict": "needs_review",
        "confidence": 0.4,
        "severity": "medium",
        "summary": f"[STUB] no LLM key configured. Prompt echo: {summary}",
        "root_cause_hypothesis": "Stub mode — no LLM analysis performed.",
        "recommended_actions": [
            "Configure ANTHROPIC_API_KEY or OPENAI_API_KEY for real analysis",
            "Verify event source and correlate with TI feeds",
        ],
        "mitre_techniques": [],
        "iocs": [],
        "tags": ["stub", "no-llm-key"],
    }
    return LlmResponse(
        text=json.dumps(out, indent=2),
        model="stub",
        provider="stub",
        usage={"input_tokens": 0, "output_tokens": 0},
        raw={"stub": True},
        latency_ms=0,
        cost_usd=0.0,
    )


# ── Provider calls (async) ───────────────────────────────────────────


async def _call_anthropic_async(
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
    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as c:
        r = await c.post("https://api.anthropic.com/v1/messages", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
    latency_ms = int((time.perf_counter() - t0) * 1000)
    text = "".join(b.get("text", "") for b in data.get("content", []) if b.get("type") == "text")
    tokens_in = data.get("usage", {}).get("input_tokens", 0)
    tokens_out = data.get("usage", {}).get("output_tokens", 0)
    _, _, total_cost = _compute_cost(data.get("model", model), tokens_in, tokens_out)
    return LlmResponse(
        text=text,
        model=data.get("model", model),
        provider="anthropic",
        usage={"input_tokens": tokens_in, "output_tokens": tokens_out},
        raw=data,
        latency_ms=latency_ms,
        cost_usd=total_cost,
    )


async def _call_openai_async(
    prompt: str, system: str | None, model: str, max_tokens: int, api_key: str
) -> LlmResponse:
    msgs: list[dict[str, str]] = []
    if system:
        msgs.append({"role": "system", "content": system})
    msgs.append({"role": "user", "content": prompt})
    body = {"model": model, "messages": msgs, "max_tokens": max_tokens}
    headers = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    t0 = time.perf_counter()
    async with httpx.AsyncClient(timeout=DEFAULT_TIMEOUT) as c:
        r = await c.post("https://api.openai.com/v1/chat/completions", json=body, headers=headers)
        r.raise_for_status()
        data = r.json()
    latency_ms = int((time.perf_counter() - t0) * 1000)
    text = data["choices"][0]["message"]["content"]
    u = data.get("usage", {})
    tokens_in = u.get("prompt_tokens", 0)
    tokens_out = u.get("completion_tokens", 0)
    _, _, total_cost = _compute_cost(data.get("model", model), tokens_in, tokens_out)
    return LlmResponse(
        text=text,
        model=data.get("model", model),
        provider="openai",
        usage={"input_tokens": tokens_in, "output_tokens": tokens_out},
        raw=data,
        latency_ms=latency_ms,
        cost_usd=total_cost,
    )


async def _attempt_with_retry(
    provider: str,
    prompt: str,
    system: str | None,
    max_tokens: int,
    api_key: str,
    model: str,
    operation: str,
) -> LlmResponse:
    """Execute le call provider avec retry exponentiel.

    Leve la derniere exception (Retryable ou Fatal) si toutes les tentatives echouent.
    """
    last_exc: Exception | None = None
    for attempt in range(MAX_RETRIES):
        try:
            if provider == "anthropic":
                resp = await _call_anthropic_async(prompt, system, model, max_tokens, api_key)
            else:
                resp = await _call_openai_async(prompt, system, model, max_tokens, api_key)
            _log_cost(
                provider=provider,
                model=resp.model,
                operation=operation,
                tokens_in=resp.usage.get("input_tokens", 0),
                tokens_out=resp.usage.get("output_tokens", 0),
                latency_ms=resp.latency_ms,
                success=True,
            )
            return resp
        except Exception as e:
            classified = _classify(e)
            last_exc = classified
            if isinstance(classified, _Fatal):
                _log_cost(
                    provider=provider,
                    model=model,
                    operation=operation,
                    tokens_in=0,
                    tokens_out=0,
                    latency_ms=0,
                    success=False,
                    error_msg=str(classified),
                )
                raise classified
            # Retryable
            if attempt == MAX_RETRIES - 1:
                break
            wait = (
                classified.retry_after
                if classified.retry_after is not None
                else BACKOFF_SCHEDULE[attempt]
            )
            logger.warning(
                "LLM %s attempt %d/%d failed (%s) — retry in %.1fs",
                provider, attempt + 1, MAX_RETRIES, classified, wait,
            )
            await asyncio.sleep(wait)

    # Toutes tentatives epuisees
    _log_cost(
        provider=provider,
        model=model,
        operation=operation,
        tokens_in=0,
        tokens_out=0,
        latency_ms=0,
        success=False,
        error_msg=str(last_exc) if last_exc else "unknown",
    )
    assert last_exc is not None
    raise last_exc


# ── Entry point async (avec fallback) ─────────────────────────────────


async def call(
    prompt: str,
    system: str | None = None,
    max_tokens: int = 1024,
    prefer: str | None = None,
    operation: str = "raw",
) -> LlmResponse:
    """Appel LLM async avec retry + fallback automatique entre providers.

    Args:
        prompt: contenu user
        system: prompt systeme (optionnel)
        max_tokens: limite tokens output
        prefer: 'anthropic' | 'openai' | 'stub' | None (auto)
        operation: tag pour cost log ('triage' | 'rag' | 'rule_gen' | 'raw' | ...)
    """
    anth_key = os.environ.get("ANTHROPIC_API_KEY")
    oai_key = os.environ.get("OPENAI_API_KEY")

    if prefer == "stub":
        return _stub_response(prompt, system)

    chosen = prefer
    if chosen is None:
        chosen = "anthropic" if anth_key else ("openai" if oai_key else "stub")

    if chosen == "stub":
        return _stub_response(prompt, system)
    if not anth_key and not oai_key:
        return _stub_response(prompt, system)

    # Liste des providers a essayer (primary puis fallback)
    order: list[tuple[str, str | None, str]] = []
    if chosen == "anthropic" and anth_key:
        model = os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")
        order.append(("anthropic", anth_key, model))
        if oai_key:
            order.append(("openai", oai_key, os.environ.get("OPENAI_MODEL", "gpt-4o-mini")))
    elif chosen == "openai" and oai_key:
        model = os.environ.get("OPENAI_MODEL", "gpt-4o-mini")
        order.append(("openai", oai_key, model))
        if anth_key:
            order.append(("anthropic", anth_key, os.environ.get("ANTHROPIC_MODEL", "claude-haiku-4-5-20251001")))
    else:
        # Cas degrade : pas de cle dispo
        return _stub_response(prompt, system)

    last_err: Exception | None = None
    for provider, key, model in order:
        try:
            return await _attempt_with_retry(
                provider, prompt, system, max_tokens, key or "", model, operation
            )
        except Exception as e:
            last_err = e
            logger.warning("LLM provider %s exhausted retries (%s) — trying next fallback", provider, e)
            continue

    # Tous les providers ont echoue : retour stub avec marker error
    logger.error("All LLM providers failed, returning stub. Last error: %s", last_err)
    fallback = _stub_response(prompt, system)
    fallback.text = json.dumps(
        {
            "verdict": "needs_review",
            "confidence": 0.0,
            "severity": "medium",
            "summary": f"[LLM-FAILURE] All providers exhausted. Last error: {last_err}",
            "root_cause_hypothesis": "LLM unavailable",
            "recommended_actions": ["Inspect provider API keys/quotas", "Retry later"],
            "mitre_techniques": [],
            "iocs": [],
            "tags": ["llm-failure"],
        },
        indent=2,
    )
    return fallback


# ── Wrapper sync (compat existant) ───────────────────────────────────


def call_llm(
    prompt: str,
    system: str | None = None,
    max_tokens: int = 1024,
    prefer: str | None = None,
    operation: str = "raw",
) -> LlmResponse:
    """Wrapper synchrone autour de `call()`. Pour code sync (tests, modules legacy).

    Si appele depuis une boucle async deja active, leve RuntimeError —
    utiliser `await call(...)` directement dans ce cas.
    """
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None
    if loop and loop.is_running():
        raise RuntimeError(
            "call_llm() is sync; you are inside an async context. Use `await call(...)` instead."
        )
    return asyncio.run(call(prompt, system=system, max_tokens=max_tokens, prefer=prefer, operation=operation))


# ── Status / parse ───────────────────────────────────────────────────


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
        "retry_max": MAX_RETRIES,
        "backoff_schedule_s": list(BACKOFF_SCHEDULE),
        "pricing_models_known": len(MODEL_PRICING),
    }


def parse_json_response(text: str) -> dict[str, Any] | None:
    """Best-effort JSON extraction d'une reponse LLM."""
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


# ── Cost agregation read API ─────────────────────────────────────────


def get_daily_cost(day: str | None = None) -> dict[str, Any]:
    """Retourne l'agregation Redis (sinon recalcule)."""
    try:
        from apps.api.cache import _get_redis
        if day is None:
            day = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        r = _get_redis()
        if r is not None:
            try:
                cached = r.get(f"ai:cost:daily:{day}")
                if cached:
                    return json.loads(cached)
            except Exception:
                pass
        return _refresh_daily_cost_cache(day) or {"day": day, "total_usd": 0.0}
    except Exception:
        return {"day": day, "total_usd": 0.0}
