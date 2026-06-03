"""Individual pipeline stage implementations.

Each stage is a class with an async ``execute(ctx) -> ctx`` method.
Stages must be idempotent and fault-tolerant.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import re
import uuid
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from typing import Any

from apps.api.pipeline.context import EventContext

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Base
# ---------------------------------------------------------------------------


class BaseStage(ABC):
    """Abstract base for all pipeline stages."""

    name: str = "base"

    @abstractmethod
    async def execute(self, ctx: EventContext) -> EventContext: ...


# ---------------------------------------------------------------------------
# 1. INGEST
# ---------------------------------------------------------------------------


class IngestStage(BaseStage):
    name = "ingest"

    async def execute(self, ctx: EventContext) -> EventContext:
        raw = ctx.raw
        if raw is None:
            raise ValueError("No raw data provided")

        # Normalise to string if dict/bytes
        if isinstance(raw, bytes):
            raw = raw.decode("utf-8", errors="replace")
        if isinstance(raw, dict):
            # Pre-parsed JSON event
            ctx.parsed = dict(raw)
            raw = json.dumps(raw, default=str)
            ctx.raw = raw

        # Assign event ID and timestamp if missing
        if not ctx.parsed.get("id"):
            ctx.parsed["id"] = str(uuid.uuid4())
        if not ctx.parsed.get("ts"):
            ctx.parsed["ts"] = datetime.now(UTC)
        ctx.context_id = ctx.parsed["id"]
        return ctx


# ---------------------------------------------------------------------------
# 2. PARSE
# ---------------------------------------------------------------------------


class ParseStage(BaseStage):
    name = "parse"

    async def execute(self, ctx: EventContext) -> EventContext:
        # If already parsed (came in as dict), skip
        if ctx.parsed.get("event_type") and ctx.parsed.get("source"):
            return ctx

        raw_str = ctx.raw if isinstance(ctx.raw, str) else str(ctx.raw)
        try:
            from apps.api.parsers import parse_line

            result = await asyncio.to_thread(parse_line, raw_str)
            if result:
                # Merge, keeping existing values
                for k, v in result.items():
                    if not ctx.parsed.get(k):
                        ctx.parsed[k] = v
        except Exception:
            logger.debug("Parse stage: no parser matched, using raw passthrough")
            if not ctx.parsed.get("source"):
                ctx.parsed["source"] = "unknown"
            if not ctx.parsed.get("event_type"):
                ctx.parsed["event_type"] = "unknown"
            if not ctx.parsed.get("severity"):
                ctx.parsed["severity"] = "low"
            if not ctx.parsed.get("message"):
                ctx.parsed["message"] = raw_str[:2000]
            ctx.parsed.setdefault("raw", raw_str)

        return ctx


# ---------------------------------------------------------------------------
# 3. ENRICH_GEO
# ---------------------------------------------------------------------------


class GeoEnrichStage(BaseStage):
    name = "enrich_geo"

    _PRIVATE_RE = re.compile(r"^(10\.|172\.(1[6-9]|2\d|3[01])\.|192\.168\.|127\.|::1|fe80:|fd)")

    async def execute(self, ctx: EventContext) -> EventContext:
        geo_results: dict[str, Any] = {}
        for field_name in ("src_ip", "dst_ip"):
            ip = ctx.parsed.get(field_name)
            if not ip or self._PRIVATE_RE.match(ip):
                continue
            info = await self._lookup(ip)
            if info:
                geo_results[field_name] = info

        if geo_results:
            ctx.add_enrichment("geo", geo_results)
        return ctx

    async def _lookup(self, ip: str) -> dict[str, Any] | None:
        """Attempt GeoIP lookup via geoip2 (MaxMind) with graceful fallback."""
        try:
            import geoip2.database  # type: ignore[import-untyped]

            reader = geoip2.database.Reader("/usr/share/GeoIP/GeoLite2-City.mmdb")
            resp = reader.city(ip)
            return {
                "country": resp.country.iso_code,
                "country_name": resp.country.name,
                "city": resp.city.name,
                "latitude": resp.location.latitude,
                "longitude": resp.location.longitude,
            }
        except Exception:
            logger.debug("stages: ignored exception", exc_info=True)
        # Fallback: return None (no geo data available)
        return None


# ---------------------------------------------------------------------------
# 4. ENRICH_TI
# ---------------------------------------------------------------------------


class TIEnrichStage(BaseStage):
    name = "enrich_ti"

    async def execute(self, ctx: EventContext) -> EventContext:
        indicators: list[tuple[str, str]] = []  # (type, value)

        for field_name in ("src_ip", "dst_ip"):
            ip = ctx.parsed.get(field_name)
            if ip:
                indicators.append(("ip", ip))

        # Extract domain from message if present
        message = ctx.parsed.get("message", "") or ""
        domain_re = re.compile(r"(?:https?://)?([a-zA-Z0-9.-]+\.[a-zA-Z]{2,})")
        for domain in domain_re.findall(message):
            indicators.append(("domain", domain))

        if not indicators:
            return ctx

        best_score = 0
        all_tags: list[str] = []
        provider_results: list[dict] = []

        try:
            from apps.api.db.session import SessionLocal
            from apps.api.threat_intel.enrichment import _lookup_ip

            db = SessionLocal()
            try:
                for ind_type, ind_value in indicators:
                    if ind_type == "ip":
                        result = await _lookup_ip(ind_value, db)
                        if result:
                            best_score = max(best_score, result.risk_score)
                            all_tags.extend(result.tags)
                            provider_results.append(
                                {
                                    "indicator": ind_value,
                                    "type": ind_type,
                                    "source": result.source,
                                    "risk_score": result.risk_score,
                                    "is_malicious": result.is_malicious,
                                    "tags": result.tags,
                                }
                            )
            finally:
                db.close()
        except Exception:
            logger.debug("TI enrichment skipped (providers unavailable)")

        ti_data = {
            "risk_score": best_score,
            "tags": list(set(all_tags))[:20],
            "indicators_checked": len(indicators),
            "results": provider_results,
        }
        ctx.add_enrichment("ti", ti_data)
        return ctx


# ---------------------------------------------------------------------------
# 5. ENRICH_ASSET
# ---------------------------------------------------------------------------


class AssetEnrichStage(BaseStage):
    name = "enrich_asset"

    async def execute(self, ctx: EventContext) -> EventContext:
        asset_info: dict[str, Any] = {}

        # Try to lookup by IP or hostname from parsed data
        for field_name in ("src_ip", "dst_ip", "username"):
            value = ctx.parsed.get(field_name)
            if not value:
                continue
            info = await self._lookup_asset(value)
            if info:
                asset_info[field_name] = info

        if asset_info:
            ctx.add_enrichment("asset", asset_info)
        return ctx

    async def _lookup_asset(self, identifier: str) -> dict[str, Any] | None:
        """Lookup asset in inventory. Returns None if not found."""
        try:
            from sqlalchemy import text

            from apps.api.db.session import SessionLocal

            db = SessionLocal()
            try:
                # Check if asset table exists and query it
                row = db.execute(
                    text(
                        "SELECT hostname, owner, criticality, business_unit "
                        "FROM assets WHERE ip_address = :ip OR hostname = :host "
                        "LIMIT 1"
                    ),
                    {"ip": identifier, "host": identifier},
                ).first()
                if row:
                    return {
                        "hostname": row[0],
                        "owner": row[1],
                        "criticality": row[2],
                        "business_unit": row[3],
                    }
            except Exception:
                logger.debug("stages: ignored exception", exc_info=True)
            finally:
                db.close()
        except Exception:
            logger.debug("stages: ignored exception", exc_info=True)
        return None


# ---------------------------------------------------------------------------
# 6. CLASSIFY
# ---------------------------------------------------------------------------


class ClassifyStage(BaseStage):
    name = "classify"

    # Keyword-based classification rules
    _PATTERNS: list[tuple[str, list[str]]] = [
        (
            "authentication",
            ["login", "logon", "logoff", "logout", "auth", "password", "credential", "sso"],
        ),
        ("network", ["firewall", "connection", "tcp", "udp", "dns", "port", "traffic", "packet"]),
        ("process", ["process", "exec", "spawn", "cmd", "powershell", "bash", "script"]),
        ("file", ["file", "write", "read", "delete", "create", "modify", "rename", "copy"]),
        ("dns", ["dns", "nslookup", "resolve", "query", "domain"]),
        ("web", ["http", "https", "url", "request", "response", "web", "api", "GET", "POST"]),
        ("email", ["email", "smtp", "imap", "phishing", "attachment", "mail"]),
        ("system", ["syslog", "kernel", "boot", "shutdown", "service", "daemon"]),
    ]

    async def execute(self, ctx: EventContext) -> EventContext:
        # If event_type is already specific, skip
        current = ctx.parsed.get("event_type", "unknown")
        if current and current != "unknown":
            return ctx

        # Try ML classification first if enabled
        try:
            from apps.api.pipeline.config import get_pipeline_config

            cfg = get_pipeline_config()
            if cfg.ml_classification_enabled:
                ml_result = await self._ml_classify(ctx)
                if ml_result:
                    ctx.parsed["event_type"] = ml_result
                    ctx.add_enrichment(
                        "classification",
                        {
                            "method": "ml",
                            "event_type": ml_result,
                        },
                    )
                    return ctx
        except Exception:
            logger.debug("stages: ignored exception", exc_info=True)

        # Rule-based fallback
        text_to_check = " ".join(
            [
                ctx.parsed.get("message", ""),
                ctx.parsed.get("source", ""),
                ctx.parsed.get("raw", ""),
            ]
        ).lower()

        best_type = "unknown"
        best_score = 0
        for event_type, keywords in self._PATTERNS:
            score = sum(1 for kw in keywords if kw in text_to_check)
            if score > best_score:
                best_score = score
                best_type = event_type

        ctx.parsed["event_type"] = best_type
        ctx.add_enrichment(
            "classification",
            {
                "method": "rule_based",
                "event_type": best_type,
                "confidence": min(best_score / 3.0, 1.0),
            },
        )
        return ctx

    async def _ml_classify(self, ctx: EventContext) -> str | None:
        """Attempt ML-based classification. Returns None on failure."""
        try:
            from apps.api.detection.ml_anomaly import classify_event

            return await asyncio.to_thread(classify_event, ctx.parsed)
        except Exception:
            return None


# ---------------------------------------------------------------------------
# 7. SCORE
# ---------------------------------------------------------------------------


class ScoreStage(BaseStage):
    name = "score"

    _SEVERITY_SCORES = {"critical": 40, "high": 30, "medium": 15, "low": 5}

    async def execute(self, ctx: EventContext) -> EventContext:
        score = 0

        # 1. TI risk score (0-100) — weight 40%
        ti = ctx.enrichments.get("ti", {})
        ti_score = ti.get("risk_score", 0)
        score += int(ti_score * 0.4)

        # 2. Severity (weight 25%)
        severity = ctx.parsed.get("severity", "low")
        score += self._SEVERITY_SCORES.get(severity, 5)

        # 3. Asset criticality (weight 20%)
        asset = ctx.enrichments.get("asset", {})
        for _, info in asset.items():
            if isinstance(info, dict):
                crit = info.get("criticality", "low")
                crit_scores = {"critical": 20, "high": 15, "medium": 10, "low": 5}
                score += crit_scores.get(crit, 5)
                break

        # 4. Time-of-day anomaly (weight 10%)
        ts = ctx.parsed.get("ts")
        if isinstance(ts, datetime):
            hour = ts.hour
            if hour < 6 or hour > 22:  # off-hours
                score += 10

        # 5. IOC/TI tag bonus (weight 5%)
        if ti.get("tags"):
            score += 5

        ctx.score = min(score, 100)
        ctx.add_enrichment(
            "score_breakdown",
            {
                "ti_component": int(ti_score * 0.4),
                "severity_component": self._SEVERITY_SCORES.get(severity, 5),
                "asset_component": score
                - int(ti_score * 0.4)
                - self._SEVERITY_SCORES.get(severity, 5),
                "total": ctx.score,
            },
        )
        return ctx


# ---------------------------------------------------------------------------
# 8. DETECT
# ---------------------------------------------------------------------------


class DetectStage(BaseStage):
    name = "detect"

    async def execute(self, ctx: EventContext) -> EventContext:
        if ctx.dry_run:
            return ctx

        detections: list[dict] = []

        # Run SIGMA rules
        try:
            detections.extend(await self._run_sigma(ctx))
        except Exception:
            logger.debug("SIGMA detection skipped")

        # Run custom detection rules
        try:
            detections.extend(await self._run_custom_rules(ctx))
        except Exception:
            logger.debug("Custom detection rules skipped")

        for d in detections:
            ctx.add_detection(d)
        return ctx

    async def _run_sigma(self, ctx: EventContext) -> list[dict]:
        results: list[dict] = []
        try:
            from apps.api.db.session import SessionLocal
            from apps.api.detection.sigma_engine import (
                evaluate_sigma_rule,
                get_enabled_sigma_rules,
            )

            db = SessionLocal()
            try:
                sigma_rules = get_enabled_sigma_rules(db)
                # Build a temporary Event-like object from parsed data
                mock_event = _build_mock_event(ctx.parsed)
                for sigma_rule, compiled in sigma_rules:
                    try:
                        if evaluate_sigma_rule(compiled, mock_event):
                            results.append(
                                {
                                    "type": "sigma",
                                    "rule_id": f"sigma:{sigma_rule.id}",
                                    "rule_name": sigma_rule.name,
                                    "severity": compiled.get("level", "medium"),
                                    "description": compiled.get("description", ""),
                                }
                            )
                    except Exception:
                        logger.debug("stages: ignored exception", exc_info=True)
            finally:
                db.close()
        except ImportError:
            pass
        return results

    async def _run_custom_rules(self, ctx: EventContext) -> list[dict]:
        results: list[dict] = []
        try:
            from apps.api.detection.evaluator import evaluate_rule
            from apps.api.detection.rules import get_rules

            rules = get_rules(enabled_only=True)
            mock_event = _build_mock_event(ctx.parsed)
            for rule in rules:
                try:
                    matches = evaluate_rule(rule, [mock_event])
                    if matches:
                        results.append(
                            {
                                "type": "custom",
                                "rule_id": rule.id,
                                "rule_name": rule.name,
                                "severity": rule.severity,
                            }
                        )
                except Exception:
                    logger.debug("stages: ignored exception", exc_info=True)
        except ImportError:
            pass
        return results


# ---------------------------------------------------------------------------
# 9. CORRELATE
# ---------------------------------------------------------------------------


class CorrelateStage(BaseStage):
    name = "correlate"

    async def execute(self, ctx: EventContext) -> EventContext:
        if ctx.dry_run:
            return ctx

        try:
            from apps.api.detection.correlation import get_correlation_engine

            engine = get_correlation_engine()
            mock_event = _build_mock_event(ctx.parsed)
            matches = engine.evaluate([mock_event])
            for m in matches:
                ctx.add_correlation(
                    {
                        "rule_id": m.rule_id,
                        "rule_name": m.rule_name,
                        "severity": m.severity,
                        "group_key": m.group_key,
                        "mitre_tactics": m.mitre_tactics,
                        "description": m.description,
                        "score": m.score,
                    }
                )
        except Exception:
            logger.debug("Correlation stage skipped")

        return ctx


# ---------------------------------------------------------------------------
# 10. IOC_MATCH
# ---------------------------------------------------------------------------


class IOCMatchStage(BaseStage):
    name = "ioc_match"

    async def execute(self, ctx: EventContext) -> EventContext:
        indicators: list[tuple[str, str]] = []
        for f in ("src_ip", "dst_ip"):
            v = ctx.parsed.get(f)
            if v:
                indicators.append(("ip", v))
        # Extract hashes from message
        msg = ctx.parsed.get("message", "") or ""
        for h in re.findall(r"\b[a-fA-F0-9]{32,64}\b", msg):
            if len(h) == 32:
                indicators.append(("md5", h))
            elif len(h) == 40:
                indicators.append(("sha1", h))
            elif len(h) == 64:
                indicators.append(("sha256", h))

        if not indicators:
            return ctx

        try:
            from sqlalchemy import text

            from apps.api.db.session import SessionLocal

            db = SessionLocal()
            try:
                for _ioc_type, ioc_value in indicators:
                    row = db.execute(
                        text(
                            "SELECT id, ioc_type, value, threat_type, severity, source "
                            "FROM iocs WHERE value = :val AND active = true LIMIT 1"
                        ),
                        {"val": ioc_value},
                    ).first()
                    if row:
                        ctx.add_ioc_match(
                            {
                                "ioc_id": row[0],
                                "ioc_type": row[1],
                                "value": row[2],
                                "threat_type": row[3],
                                "severity": row[4],
                                "source": row[5],
                            }
                        )
                        # Record sighting
                        try:
                            db.execute(
                                text(
                                    "UPDATE iocs SET sightings = COALESCE(sightings, 0) + 1, "
                                    "last_seen = :now WHERE id = :ioc_id"
                                ),
                                {"now": datetime.now(UTC), "ioc_id": row[0]},
                            )
                            db.commit()
                        except Exception:
                            db.rollback()
            finally:
                db.close()
        except Exception:
            logger.debug("IOC match stage skipped (table may not exist)")

        return ctx


# ---------------------------------------------------------------------------
# 11. SOAR_TRIGGER
# ---------------------------------------------------------------------------


class SOARTriggerStage(BaseStage):
    name = "soar_trigger"

    async def execute(self, ctx: EventContext) -> EventContext:
        if ctx.dry_run:
            return ctx

        # Only trigger SOAR if detections or incidents were created
        if not ctx.detections and not ctx.incidents and not ctx.correlations:
            return ctx

        try:
            from apps.api.db.session import SessionLocal
            from apps.api.soar.engine import fire_triggers

            db = SessionLocal()
            try:
                trigger_context = {
                    "severity": ctx.parsed.get("severity", "low"),
                    "event_id": ctx.parsed.get("id"),
                    "score": ctx.score,
                    "detections": ctx.detections,
                    "correlations": ctx.correlations,
                }

                # Fire on_alert triggers for each detection
                for det in ctx.detections:
                    trigger_context["rule_id"] = det.get("rule_id")
                    executions = await fire_triggers(db, "on_alert", trigger_context)
                    for exe in executions:
                        ctx.add_soar_execution(
                            {
                                "execution_id": exe.id,
                                "playbook_name": exe.playbook_name,
                                "status": exe.status,
                                "trigger": "on_alert",
                            }
                        )

                # Fire on_incident triggers for incidents
                for inc in ctx.incidents:
                    trigger_context["severity"] = inc.get("severity", "high")
                    executions = await fire_triggers(db, "on_incident", trigger_context)
                    for exe in executions:
                        ctx.add_soar_execution(
                            {
                                "execution_id": exe.id,
                                "playbook_name": exe.playbook_name,
                                "status": exe.status,
                                "trigger": "on_incident",
                            }
                        )
            finally:
                db.close()
        except Exception:
            logger.debug("SOAR trigger stage skipped")

        return ctx


# ---------------------------------------------------------------------------
# 12. ALERT
# ---------------------------------------------------------------------------


class AlertStage(BaseStage):
    name = "alert"

    async def execute(self, ctx: EventContext) -> EventContext:
        if ctx.dry_run:
            return ctx

        # Only alert if score >= 50 or detections/IOC matches exist
        should_alert = ctx.score >= 50 or ctx.detections or ctx.ioc_matches or ctx.incidents
        if not should_alert:
            return ctx

        try:
            from apps.api.alerting import async_dispatch_alert

            incident_data = {
                "id": ctx.parsed.get("id", ctx.context_id),
                "title": self._build_title(ctx),
                "severity": ctx.parsed.get("severity", "medium"),
                "description": self._build_description(ctx),
                "threat_score": ctx.score,
                "rule_id": (ctx.detections[0].get("rule_id") if ctx.detections else "pipeline"),
                "entity_key": ctx.parsed.get("src_ip") or ctx.parsed.get("username", "unknown"),
            }
            results = await async_dispatch_alert(incident_data)
            for r in results:
                ctx.add_alert(r)
        except Exception:
            logger.debug("Alert dispatch skipped")

        return ctx

    @staticmethod
    def _build_title(ctx: EventContext) -> str:
        parts = ["[PIPELINE]"]
        if ctx.detections:
            parts.append(ctx.detections[0].get("rule_name", "Detection"))
        elif ctx.ioc_matches:
            parts.append(f"IOC Match: {ctx.ioc_matches[0].get('value', '')}")
        else:
            parts.append(f"Score {ctx.score}")
        entity = ctx.parsed.get("src_ip") or ctx.parsed.get("username", "")
        if entity:
            parts.append(f"({entity})")
        return " ".join(parts)

    @staticmethod
    def _build_description(ctx: EventContext) -> str:
        lines = [f"Threat Score: {ctx.score}/100"]
        if ctx.detections:
            lines.append(f"Detections: {len(ctx.detections)}")
            for d in ctx.detections[:5]:
                lines.append(f"  - {d.get('rule_name', d.get('rule_id', ''))}")
        if ctx.ioc_matches:
            lines.append(f"IOC Matches: {len(ctx.ioc_matches)}")
        if ctx.correlations:
            lines.append(f"Correlations: {len(ctx.correlations)}")
        return "\n".join(lines)


# ---------------------------------------------------------------------------
# 13. STORE
# ---------------------------------------------------------------------------


class StoreStage(BaseStage):
    name = "store"

    async def execute(self, ctx: EventContext) -> EventContext:
        if ctx.dry_run:
            return ctx

        try:
            from apps.api.db.session import SessionLocal
            from apps.api.models.event import Event

            event_dict = ctx.to_event_dict()
            db = SessionLocal()
            try:
                # Check for duplicate
                existing = db.get(Event, event_dict.get("id"))
                if existing:
                    # Update with enrichment data
                    if ctx.score:
                        existing.ti_score = ctx.score
                    ti = ctx.enrichments.get("ti", {})
                    if ti.get("tags"):
                        existing.ti_tags = json.dumps(ti["tags"][:20])
                    db.commit()
                else:
                    event = Event(
                        id=event_dict.get("id", str(uuid.uuid4())),
                        ts=event_dict.get("ts", datetime.now(UTC)),
                        source=event_dict.get("source", "pipeline"),
                        event_type=event_dict.get("event_type", "unknown"),
                        severity=event_dict.get("severity", "low"),
                        src_ip=event_dict.get("src_ip"),
                        dst_ip=event_dict.get("dst_ip"),
                        username=event_dict.get("username"),
                        message=event_dict.get("message"),
                        raw=event_dict.get("raw"),
                        ti_score=ctx.score or event_dict.get("ti_score"),
                        ti_tags=event_dict.get("ti_tags"),
                    )
                    db.add(event)
                    db.commit()

                # Create incidents for high-severity detections
                await self._create_incidents(ctx, db)
            finally:
                db.close()
        except Exception as exc:
            logger.exception("Store stage failed: %s", exc)
            raise

        return ctx

    async def _create_incidents(self, ctx: EventContext, db: Any) -> None:
        """Create incidents from detections that warrant them."""
        from apps.api.models.incident import Incident
        from apps.api.models.incident_event import IncidentEvent

        now = datetime.now(UTC)
        severity_threshold = {"critical", "high"}

        for det in ctx.detections:
            sev = det.get("severity", "low")
            if sev not in severity_threshold:
                continue

            rule_id = det.get("rule_id", "pipeline")
            entity_key = ctx.parsed.get("src_ip") or ctx.parsed.get("username", "unknown")
            bucket = now.strftime("%Y-%m-%dT%H:%M")
            dedup = hashlib.sha256(f"{rule_id}|{entity_key}|{bucket}".encode()).hexdigest()

            try:
                existing = db.query(Incident).filter(Incident.dedup_hash == dedup).first()
                if existing:
                    continue

                incident_id = str(uuid.uuid4())
                incident = Incident(
                    id=incident_id,
                    title=f"[PIPELINE] {det.get('rule_name', rule_id)}: {entity_key}",
                    description=det.get("description", ""),
                    severity=sev,
                    status="open",
                    rule_id=rule_id,
                    entity_key=entity_key,
                    start_ts=ctx.parsed.get("ts", now),
                    end_ts=ctx.parsed.get("ts", now),
                    dedup_hash=dedup,
                    created_at=now,
                    updated_at=now,
                )
                db.add(incident)
                db.add(
                    IncidentEvent(
                        incident_id=incident_id,
                        event_id=ctx.parsed.get("id", ctx.context_id),
                    )
                )
                db.commit()

                ctx.add_incident(
                    {
                        "id": incident_id,
                        "title": incident.title,
                        "severity": sev,
                        "rule_id": rule_id,
                    }
                )
            except Exception:
                db.rollback()
                logger.debug("Incident creation skipped (dedup or error)")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_mock_event(parsed: dict[str, Any]) -> Any:
    """Build a minimal object that looks like an Event for rule evaluation."""

    class _MockEvent:
        pass

    evt = _MockEvent()
    evt.id = parsed.get("id", "")
    evt.ts = parsed.get("ts", datetime.now(UTC))
    evt.source = parsed.get("source", "")
    evt.event_type = parsed.get("event_type", "")
    evt.severity = parsed.get("severity", "low")
    evt.src_ip = parsed.get("src_ip")
    evt.dst_ip = parsed.get("dst_ip")
    evt.username = parsed.get("username")
    evt.message = parsed.get("message")
    evt.raw = parsed.get("raw")
    evt.ti_score = parsed.get("ti_score")
    evt.ti_tags = parsed.get("ti_tags")
    return evt


# ---------------------------------------------------------------------------
# Registry of all stages in pipeline order
# ---------------------------------------------------------------------------

ALL_STAGES: list[type[BaseStage]] = [
    IngestStage,
    ParseStage,
    GeoEnrichStage,
    TIEnrichStage,
    AssetEnrichStage,
    ClassifyStage,
    ScoreStage,
    DetectStage,
    CorrelateStage,
    IOCMatchStage,
    SOARTriggerStage,
    AlertStage,
    StoreStage,
]

STAGE_MAP: dict[str, type[BaseStage]] = {cls.name: cls for cls in ALL_STAGES}
