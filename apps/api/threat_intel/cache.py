"""Cache 2 niveaux pour les lookups Threat Intelligence (Redis + PostgreSQL)."""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from apps.api.threat_intel.base import TIResult

logger = logging.getLogger(__name__)

REDIS_TTL = 300  # 5 minutes
DB_TTL_HOURS = 24


def _redis_key(indicator: str, source: str) -> str:
    return f"siem:ti:cache:{source}:{indicator}"


def get_cached(indicator: str, source: str, db: Session) -> TIResult | None:
    """Cherche dans le cache Redis puis PostgreSQL."""
    # Level 1: Redis
    try:
        from apps.api.cache import get_redis_client
        r = get_redis_client()
        if r:
            raw = r.get(_redis_key(indicator, source))
            if raw:
                data = json.loads(raw)
                return TIResult(**data)
    except Exception as exc:
        logger.debug("TI cache Redis GET failed for %s/%s: %s", source, indicator, exc)

    # Level 2: PostgreSQL
    try:
        from apps.api.models.ti_cache import TICache
        row = (
            db.query(TICache)
            .filter(TICache.indicator == indicator, TICache.source == source)
            .first()
        )
        if row and row.expires_at > datetime.now(UTC):
            result = TIResult(
                indicator=row.indicator,
                source=row.source,
                risk_score=row.risk_score,
                is_malicious=row.is_malicious,
                categories=json.loads(row.categories_json) if row.categories_json else [],
                tags=json.loads(row.tags_json) if row.tags_json else [],
                total_reports=row.total_reports,
            )
            # Re-populate Redis
            _set_redis(indicator, source, result)
            return result
    except Exception:
        logger.debug("TI cache DB lookup failed for %s", indicator)

    return None


def set_cached(result: TIResult, db: Session) -> None:
    """Stocke le resultat dans les deux niveaux de cache."""
    _set_redis(result.indicator, result.source, result)
    _set_db(result, db)


def _set_redis(indicator: str, source: str, result: TIResult) -> None:
    try:
        from apps.api.cache import get_redis_client
        r = get_redis_client()
        if r:
            data = {
                "indicator": result.indicator,
                "source": result.source,
                "risk_score": result.risk_score,
                "is_malicious": result.is_malicious,
                "categories": result.categories,
                "tags": result.tags,
                "total_reports": result.total_reports,
            }
            r.setex(_redis_key(indicator, source), REDIS_TTL, json.dumps(data))
    except Exception as exc:
        logger.debug("TI cache Redis SET failed for %s: %s", source, exc)


def _set_db(result: TIResult, db: Session) -> None:
    try:
        from apps.api.models.ti_cache import TICache

        expires = datetime.now(UTC) + timedelta(hours=DB_TTL_HOURS)

        existing = (
            db.query(TICache)
            .filter(TICache.indicator == result.indicator, TICache.source == result.source)
            .first()
        )
        if existing:
            existing.risk_score = result.risk_score
            existing.is_malicious = result.is_malicious
            existing.categories_json = json.dumps(result.categories)
            existing.tags_json = json.dumps(result.tags)
            existing.total_reports = result.total_reports
            existing.expires_at = expires
            existing.updated_at = datetime.now(UTC)
        else:
            db.add(TICache(
                indicator=result.indicator,
                source=result.source,
                risk_score=result.risk_score,
                is_malicious=result.is_malicious,
                categories_json=json.dumps(result.categories),
                tags_json=json.dumps(result.tags),
                total_reports=result.total_reports,
                expires_at=expires,
            ))
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("Failed to cache TI result in DB")
