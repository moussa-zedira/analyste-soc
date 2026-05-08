"""Inter-module connectors — bridge pipeline events to other subsystems.

Each connector is a function that can be called directly or registered
as a pipeline hook.
"""

from __future__ import annotations

import hashlib
import json
import logging
import uuid
from datetime import UTC, datetime
from typing import Any

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# IOC -> TI : when IOC matched, auto-enrich with full TI details
# ---------------------------------------------------------------------------

async def ioc_to_ti_enrich(ioc_value: str, ioc_type: str = "ip") -> dict[str, Any] | None:
    """When an IOC is matched, fetch full TI details for richer context."""
    if ioc_type != "ip":
        return None
    try:
        from apps.api.db.session import SessionLocal
        from apps.api.threat_intel.enrichment import _lookup_ip

        db = SessionLocal()
        try:
            result = await _lookup_ip(ioc_value, db)
            if result:
                return {
                    "source": result.source,
                    "risk_score": result.risk_score,
                    "is_malicious": result.is_malicious,
                    "tags": result.tags,
                    "total_reports": result.total_reports,
                }
        finally:
            db.close()
    except Exception:
        logger.debug("IOC->TI enrichment failed for %s", ioc_value)
    return None


# ---------------------------------------------------------------------------
# Detection -> Incident : auto-create incident from detection with dedup
# ---------------------------------------------------------------------------

def detection_to_incident(
    db: Any,
    rule_id: str,
    rule_name: str,
    severity: str,
    entity_key: str,
    event_id: str,
    description: str = "",
) -> str | None:
    """Create an incident from a detection, with deduplication.

    Returns the incident ID if created, None if deduplicated.
    """
    from apps.api.models.incident import Incident
    from apps.api.models.incident_event import IncidentEvent

    now = datetime.now(UTC)
    bucket = now.strftime("%Y-%m-%dT%H:%M")
    dedup = hashlib.sha256(f"{rule_id}|{entity_key}|{bucket}".encode()).hexdigest()

    existing = db.query(Incident).filter(Incident.dedup_hash == dedup).first()
    if existing:
        return None

    incident_id = str(uuid.uuid4())
    incident = Incident(
        id=incident_id,
        title=f"[AUTO] {rule_name}: {entity_key}",
        description=description,
        severity=severity,
        status="open",
        rule_id=rule_id,
        entity_key=entity_key,
        start_ts=now,
        end_ts=now,
        dedup_hash=dedup,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    db.add(IncidentEvent(incident_id=incident_id, event_id=event_id))
    db.commit()
    logger.info("Auto-incident created: %s for rule %s", incident_id, rule_id)
    return incident_id


# ---------------------------------------------------------------------------
# Incident -> SOAR : auto-trigger matching playbooks
# ---------------------------------------------------------------------------

async def incident_to_soar(
    incident_id: str,
    severity: str,
    rule_id: str = "",
) -> list[dict[str, Any]]:
    """Fire SOAR playbooks matching the incident context."""
    results = []
    try:
        from apps.api.db.session import SessionLocal
        from apps.api.soar.engine import fire_triggers

        db = SessionLocal()
        try:
            context = {
                "incident_id": incident_id,
                "severity": severity,
                "rule_id": rule_id,
            }
            executions = await fire_triggers(db, "on_incident", context)
            for exe in executions:
                results.append({
                    "execution_id": exe.id,
                    "playbook_name": exe.playbook_name,
                    "status": exe.status,
                })
        finally:
            db.close()
    except Exception:
        logger.debug("Incident->SOAR connector failed for %s", incident_id)
    return results


# ---------------------------------------------------------------------------
# SOAR -> Alert : notify on playbook completion/failure
# ---------------------------------------------------------------------------

async def soar_to_alert(
    execution_id: str,
    playbook_name: str,
    status: str,
    incident_id: str | None = None,
) -> None:
    """Send alert when a SOAR playbook completes or fails."""
    if status not in ("completed", "failed"):
        return
    try:
        from apps.api.alerting import async_dispatch_alert

        alert_data = {
            "id": execution_id,
            "title": f"[SOAR] Playbook '{playbook_name}' {status}",
            "severity": "high" if status == "failed" else "medium",
            "description": (
                f"Playbook '{playbook_name}' finished with status: {status}. "
                f"Incident: {incident_id or 'N/A'}"
            ),
            "rule_id": f"soar:{playbook_name}",
            "entity_key": incident_id or execution_id,
        }
        await async_dispatch_alert(alert_data)
    except Exception:
        logger.debug("SOAR->Alert connector failed")


# ---------------------------------------------------------------------------
# Correlation -> Incident : create incident from correlation match
# ---------------------------------------------------------------------------

def correlation_to_incident(
    db: Any,
    rule_id: str,
    rule_name: str,
    severity: str,
    group_key: str,
    event_ids: list[str],
    description: str = "",
    mitre_tactics: list[str] | None = None,
) -> str | None:
    """Create an incident from a correlation match with dedup."""
    from apps.api.models.incident import Incident
    from apps.api.models.incident_event import IncidentEvent

    now = datetime.now(UTC)
    bucket = now.strftime("%Y-%m-%dT%H:%M")
    dedup = hashlib.sha256(
        f"corr:{rule_id}|{group_key}|{bucket}".encode()
    ).hexdigest()

    existing = db.query(Incident).filter(Incident.dedup_hash == dedup).first()
    if existing:
        return None

    incident_id = str(uuid.uuid4())
    full_desc = description
    if mitre_tactics:
        full_desc += f"\n\nMITRE ATT&CK: {', '.join(mitre_tactics)}"

    incident = Incident(
        id=incident_id,
        title=f"[CORR] {rule_name}: {group_key}",
        description=full_desc,
        severity=severity,
        status="open",
        rule_id=f"correlation:{rule_id}",
        entity_key=group_key,
        start_ts=now,
        end_ts=now,
        dedup_hash=dedup,
        created_at=now,
        updated_at=now,
    )
    db.add(incident)
    for eid in event_ids:
        db.add(IncidentEvent(incident_id=incident_id, event_id=eid))
    db.commit()
    return incident_id


# ---------------------------------------------------------------------------
# Event -> CQL : make pipeline events immediately searchable
# ---------------------------------------------------------------------------

def event_to_cql_index(event_dict: dict[str, Any]) -> None:
    """Push event data to CQL search index (Redis-based) for fast lookup."""
    try:
        from apps.api.cache import get_redis_client

        r = get_redis_client()
        if r is None:
            return
        # Store in a sorted set keyed by timestamp for range queries
        key = "cql:events:index"
        ts = event_dict.get("ts")
        if isinstance(ts, datetime):
            score = ts.timestamp()
        else:
            score = datetime.now(UTC).timestamp()
        r.zadd(key, {json.dumps(event_dict, default=str)[:4000]: score})
        # Trim to last 100k events
        r.zremrangebyrank(key, 0, -100001)
    except Exception:
        logger.debug("connectors: ignored exception", exc_info=True)


# ---------------------------------------------------------------------------
# Finding -> IOC : auto-create IOC from pentest findings
# ---------------------------------------------------------------------------

def finding_to_ioc(
    db: Any,
    value: str,
    ioc_type: str,
    threat_type: str = "pentest_finding",
    severity: str = "high",
    source: str = "pipeline",
) -> str | None:
    """Create an IOC entry from a pentest finding."""
    try:
        from sqlalchemy import text

        # Check existing
        existing = db.execute(
            text("SELECT id FROM iocs WHERE value = :val"),
            {"val": value},
        ).first()
        if existing:
            return None

        ioc_id = str(uuid.uuid4())
        now = datetime.now(UTC)
        db.execute(
            text(
                "INSERT INTO iocs (id, ioc_type, value, threat_type, severity, "
                "source, active, sightings, created_at, updated_at) "
                "VALUES (:id, :t, :v, :tt, :sev, :src, true, 0, :now, :now)"
            ),
            {
                "id": ioc_id,
                "t": ioc_type,
                "v": value,
                "tt": threat_type,
                "sev": severity,
                "src": source,
                "now": now,
            },
        )
        db.commit()
        return ioc_id
    except Exception:
        db.rollback()
        logger.debug("Finding->IOC connector failed for %s", value)
        return None


# ---------------------------------------------------------------------------
# Scan -> Event : convert scan results to events for pipeline processing
# ---------------------------------------------------------------------------

def scan_result_to_event(scan_result: dict[str, Any]) -> dict[str, Any]:
    """Convert a scan result dict into a raw event dict for pipeline ingestion."""
    return {
        "id": str(uuid.uuid4()),
        "ts": scan_result.get("timestamp", datetime.now(UTC)),
        "source": f"scanner:{scan_result.get('scanner', 'unknown')}",
        "event_type": "scan_result",
        "severity": scan_result.get("severity", "medium"),
        "src_ip": scan_result.get("target_ip"),
        "dst_ip": None,
        "username": None,
        "message": scan_result.get("finding", scan_result.get("title", "")),
        "raw": json.dumps(scan_result, default=str),
    }
