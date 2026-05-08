"""IOC Lifecycle Management — CRUD, etats, enrichissement, import/export.

Gere le cycle de vie complet des IOC: creation, deduplication, expiration,
revocation, enrichissement automatique, import/export multi-format.
"""

from __future__ import annotations

import csv
import io
import json
import logging
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from apps.api.models.ioc import IOC, IOCRelationship, IOCSighting
from apps.api.threat_intel.stix import (
    generate_stix_id,
    ioc_to_stix,
    make_bundle,
    parse_bundle,
    stix_to_ioc,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Valid IOC types
# ---------------------------------------------------------------------------

IOC_TYPES = {
    "ip", "domain", "url", "hash_md5", "hash_sha1", "hash_sha256",
    "email", "filename", "mutex", "registry_key", "user_agent",
    "cidr", "asn", "cve", "ja3",
}

IOC_STATES = {"active", "expired", "revoked", "false_positive"}

TLP_LEVELS = {"WHITE", "GREEN", "AMBER", "AMBER+STRICT", "RED"}

# Default TTLs per IOC type (in hours)
DEFAULT_TTL: dict[str, int] = {
    "ip": 168,        # 7 days
    "domain": 720,    # 30 days
    "url": 72,        # 3 days
    "hash_md5": 8760, # 1 year
    "hash_sha1": 8760,
    "hash_sha256": 8760,
    "email": 2160,    # 90 days
    "filename": 720,
    "mutex": 2160,
    "registry_key": 2160,
    "user_agent": 720,
    "cidr": 168,
    "asn": 2160,
    "cve": 8760,
    "ja3": 720,
}


# ═══════════════════════════════════════════════════════════════════════════
# CRUD
# ═══════════════════════════════════════════════════════════════════════════

def create_ioc(
    db: Session,
    ioc_type: str,
    value: str,
    source: str = "manual",
    confidence: int = 50,
    tlp: str = "AMBER",
    tags: list[str] | None = None,
    mitre_techniques: list[str] | None = None,
    kill_chain_phase: str | None = None,
    metadata: dict | None = None,
    ttl_hours: int | None = None,
    enrich: bool = False,
) -> IOC:
    """Create a new IOC or update if duplicate exists."""
    if ioc_type not in IOC_TYPES:
        raise ValueError(f"Invalid IOC type: {ioc_type}. Valid: {IOC_TYPES}")
    if tlp.upper() not in TLP_LEVELS:
        raise ValueError(f"Invalid TLP: {tlp}. Valid: {TLP_LEVELS}")
    confidence = max(0, min(100, confidence))

    # Deduplication
    existing = db.query(IOC).filter(IOC.type == ioc_type, IOC.value == value).first()
    if existing:
        # Update last_seen and merge data
        existing.last_seen = datetime.now(UTC)
        existing.updated_at = datetime.now(UTC)
        if confidence > existing.confidence:
            existing.confidence = confidence
        # Merge tags
        old_tags = json.loads(existing.tags_json) if existing.tags_json else []
        merged_tags = list(set(old_tags + (tags or [])))
        existing.tags_json = json.dumps(merged_tags)
        # Merge MITRE
        old_mitre = json.loads(existing.mitre_techniques_json) if existing.mitre_techniques_json else []
        merged_mitre = list(set(old_mitre + (mitre_techniques or [])))
        existing.mitre_techniques_json = json.dumps(merged_mitre)
        if existing.state == "expired":
            existing.state = "active"
        db.commit()
        db.refresh(existing)
        return existing

    now = datetime.now(UTC)
    ttl = ttl_hours or DEFAULT_TTL.get(ioc_type, 720)
    expiry = now + timedelta(hours=ttl)

    stix_id = generate_stix_id("indicator", f"{ioc_type}:{value}")

    ioc = IOC(
        type=ioc_type,
        value=value,
        state="active",
        confidence=confidence,
        tlp=tlp.upper(),
        source=source,
        tags_json=json.dumps(tags or []),
        mitre_techniques_json=json.dumps(mitre_techniques or []),
        kill_chain_phase=kill_chain_phase,
        metadata_json=json.dumps(metadata or {}),
        stix_id=stix_id,
        first_seen=now,
        last_seen=now,
        expiry=expiry,
        created_at=now,
        updated_at=now,
    )
    db.add(ioc)
    db.commit()
    db.refresh(ioc)
    return ioc


def get_ioc(db: Session, ioc_id: int) -> IOC | None:
    return db.get(IOC, ioc_id)


def list_iocs(
    db: Session,
    ioc_type: str | None = None,
    state: str | None = None,
    confidence_min: int | None = None,
    confidence_max: int | None = None,
    tlp: str | None = None,
    source: str | None = None,
    tag: str | None = None,
    search: str | None = None,
    offset: int = 0,
    limit: int = 50,
) -> tuple[list[IOC], int]:
    """List IOCs with filters. Returns (items, total_count)."""
    q = db.query(IOC)

    if ioc_type:
        q = q.filter(IOC.type == ioc_type)
    if state:
        q = q.filter(IOC.state == state)
    if confidence_min is not None:
        q = q.filter(IOC.confidence >= confidence_min)
    if confidence_max is not None:
        q = q.filter(IOC.confidence <= confidence_max)
    if tlp:
        q = q.filter(IOC.tlp == tlp.upper())
    if source:
        q = q.filter(IOC.source == source)
    if tag:
        q = q.filter(IOC.tags_json.contains(tag))
    if search:
        q = q.filter(or_(
            IOC.value.contains(search),
            IOC.source.contains(search),
            IOC.tags_json.contains(search),
        ))

    total = q.count()
    items = q.order_by(IOC.last_seen.desc()).offset(offset).limit(limit).all()
    return items, total


def update_ioc(
    db: Session,
    ioc_id: int,
    **kwargs: Any,
) -> IOC | None:
    """Update IOC fields."""
    ioc = db.get(IOC, ioc_id)
    if not ioc:
        return None

    for key, val in kwargs.items():
        if key == "tags" and isinstance(val, list):
            ioc.tags_json = json.dumps(val)
        elif key == "mitre_techniques" and isinstance(val, list):
            ioc.mitre_techniques_json = json.dumps(val)
        elif key == "metadata" and isinstance(val, dict):
            ioc.metadata_json = json.dumps(val)
        elif hasattr(ioc, key):
            setattr(ioc, key, val)

    ioc.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(ioc)
    return ioc


def delete_ioc(db: Session, ioc_id: int) -> bool:
    ioc = db.get(IOC, ioc_id)
    if not ioc:
        return False
    db.delete(ioc)
    db.commit()
    return True


def revoke_ioc(db: Session, ioc_id: int) -> IOC | None:
    return update_ioc(db, ioc_id, state="revoked")


def mark_false_positive(db: Session, ioc_id: int) -> IOC | None:
    return update_ioc(db, ioc_id, state="false_positive")


# ═══════════════════════════════════════════════════════════════════════════
# Expiration
# ═══════════════════════════════════════════════════════════════════════════

def expire_stale_iocs(db: Session) -> int:
    """Mark IOCs past their expiry as expired. Returns count."""
    now = datetime.now(UTC)
    count = (
        db.query(IOC)
        .filter(IOC.state == "active", IOC.expiry is not None, IOC.expiry < now)
        .update({"state": "expired", "updated_at": now})
    )
    db.commit()
    return count


# ═══════════════════════════════════════════════════════════════════════════
# Sightings
# ═══════════════════════════════════════════════════════════════════════════

def record_sighting(
    db: Session,
    ioc_id: int,
    event_id: str | None = None,
    source: str = "internal",
    count: int = 1,
) -> IOCSighting:
    sighting = IOCSighting(
        ioc_id=ioc_id,
        event_id=event_id,
        source=source,
        count=count,
    )
    db.add(sighting)
    # Update last_seen on the IOC
    ioc = db.get(IOC, ioc_id)
    if ioc:
        ioc.last_seen = datetime.now(UTC)
    db.commit()
    db.refresh(sighting)
    return sighting


def get_sightings(db: Session, ioc_id: int, limit: int = 100) -> list[IOCSighting]:
    return (
        db.query(IOCSighting)
        .filter(IOCSighting.ioc_id == ioc_id)
        .order_by(IOCSighting.timestamp.desc())
        .limit(limit)
        .all()
    )


# ═══════════════════════════════════════════════════════════════════════════
# Relationships
# ═══════════════════════════════════════════════════════════════════════════

RELATIONSHIP_TYPES = {
    "related-to", "derived-from", "uses", "targets", "attributed-to",
    "communicates-with", "hosts", "delivers", "exploits",
}


def add_relationship(
    db: Session,
    source_ioc_id: int,
    target_ioc_id: int,
    relationship_type: str,
    confidence: int = 50,
) -> IOCRelationship:
    if relationship_type not in RELATIONSHIP_TYPES:
        raise ValueError(f"Invalid relationship type: {relationship_type}")
    rel = IOCRelationship(
        source_ioc_id=source_ioc_id,
        target_ioc_id=target_ioc_id,
        relationship_type=relationship_type,
        confidence=confidence,
    )
    db.add(rel)
    db.commit()
    db.refresh(rel)
    return rel


def get_related_iocs(db: Session, ioc_id: int) -> list[dict]:
    """Get all IOCs related to the given IOC (bidirectional)."""
    rels_out = db.query(IOCRelationship).filter(IOCRelationship.source_ioc_id == ioc_id).all()
    rels_in = db.query(IOCRelationship).filter(IOCRelationship.target_ioc_id == ioc_id).all()

    results = []
    for r in rels_out:
        target = db.get(IOC, r.target_ioc_id)
        if target:
            results.append({
                "relationship_id": r.id,
                "direction": "outgoing",
                "relationship_type": r.relationship_type,
                "ioc": ioc_to_dict(target),
            })
    for r in rels_in:
        src = db.get(IOC, r.source_ioc_id)
        if src:
            results.append({
                "relationship_id": r.id,
                "direction": "incoming",
                "relationship_type": r.relationship_type,
                "ioc": ioc_to_dict(src),
            })
    return results


# ═══════════════════════════════════════════════════════════════════════════
# Import / Export
# ═══════════════════════════════════════════════════════════════════════════

def bulk_import_stix(db: Session, data: dict | str, source: str = "stix_import") -> dict:
    """Import IOCs from STIX 2.1 bundle. Returns stats."""
    objects = parse_bundle(data)
    created = 0
    updated = 0
    skipped = 0

    for obj in objects:
        ioc_dict = stix_to_ioc(obj)
        if not ioc_dict:
            skipped += 1
            continue
        existing = db.query(IOC).filter(
            IOC.type == ioc_dict["type"], IOC.value == ioc_dict["value"]
        ).first()
        if existing:
            updated += 1
        else:
            created += 1
        create_ioc(
            db,
            ioc_type=ioc_dict["type"],
            value=ioc_dict["value"],
            source=source,
            confidence=ioc_dict.get("confidence", 50),
            tlp=ioc_dict.get("tlp", "AMBER"),
            tags=ioc_dict.get("tags", []),
            mitre_techniques=ioc_dict.get("mitre_techniques", []),
            kill_chain_phase=ioc_dict.get("kill_chain_phase"),
        )

    return {"created": created, "updated": updated, "skipped": skipped, "total": len(objects)}


def bulk_import_csv(db: Session, csv_text: str, source: str = "csv_import") -> dict:
    """Import IOCs from CSV. Expected columns: type, value, [confidence, tlp, tags]."""
    reader = csv.DictReader(io.StringIO(csv_text))
    created = 0
    updated = 0
    errors = 0

    for row in reader:
        ioc_type = row.get("type", "").strip()
        value = row.get("value", "").strip()
        if not ioc_type or not value:
            errors += 1
            continue
        if ioc_type not in IOC_TYPES:
            errors += 1
            continue

        existing = db.query(IOC).filter(IOC.type == ioc_type, IOC.value == value).first()
        if existing:
            updated += 1
        else:
            created += 1

        tags = []
        if row.get("tags"):
            tags = [t.strip() for t in row["tags"].split(";") if t.strip()]

        try:
            create_ioc(
                db,
                ioc_type=ioc_type,
                value=value,
                source=source,
                confidence=int(row.get("confidence", 50)),
                tlp=row.get("tlp", "AMBER").upper(),
                tags=tags,
            )
        except Exception:
            errors += 1

    return {"created": created, "updated": updated, "errors": errors}


def bulk_import_text(db: Session, text: str, ioc_type: str = "ip", source: str = "text_import") -> dict:
    """Import IOCs from plain text (one per line)."""
    created = 0
    skipped = 0
    for line in text.splitlines():
        val = line.strip()
        if not val or val.startswith("#"):
            continue
        existing = db.query(IOC).filter(IOC.type == ioc_type, IOC.value == val).first()
        if existing:
            skipped += 1
            create_ioc(db, ioc_type=ioc_type, value=val, source=source)
        else:
            created += 1
            create_ioc(db, ioc_type=ioc_type, value=val, source=source)

    return {"created": created, "skipped": skipped}


def export_stix_bundle(db: Session, state: str | None = "active") -> dict:
    """Export all (active) IOCs as a STIX 2.1 Bundle."""
    q = db.query(IOC)
    if state:
        q = q.filter(IOC.state == state)
    iocs = q.all()
    stix_objects = [ioc_to_stix(ioc_to_dict(i)) for i in iocs]
    return make_bundle(stix_objects)


def export_csv(db: Session, state: str | None = "active") -> str:
    """Export IOCs as CSV."""
    q = db.query(IOC)
    if state:
        q = q.filter(IOC.state == state)
    iocs = q.all()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["type", "value", "state", "confidence", "tlp", "source", "tags", "first_seen", "last_seen"])
    for ioc in iocs:
        tags = ""
        if ioc.tags_json:
            try:
                tags = ";".join(json.loads(ioc.tags_json))
            except Exception as exc:
                logger.warning("Malformed tags_json on IOC %s during CSV export: %s", ioc.id, exc)
        writer.writerow([
            ioc.type, ioc.value, ioc.state, ioc.confidence, ioc.tlp,
            ioc.source, tags,
            ioc.first_seen.isoformat() if ioc.first_seen else "",
            ioc.last_seen.isoformat() if ioc.last_seen else "",
        ])
    return output.getvalue()


# ═══════════════════════════════════════════════════════════════════════════
# Statistics
# ═══════════════════════════════════════════════════════════════════════════

def get_ioc_stats(db: Session) -> dict:
    """Compute IOC statistics."""
    total = db.query(func.count(IOC.id)).scalar() or 0
    by_type = dict(
        db.query(IOC.type, func.count(IOC.id)).group_by(IOC.type).all()
    )
    by_state = dict(
        db.query(IOC.state, func.count(IOC.id)).group_by(IOC.state).all()
    )
    by_tlp = dict(
        db.query(IOC.tlp, func.count(IOC.id)).group_by(IOC.tlp).all()
    )
    by_source = dict(
        db.query(IOC.source, func.count(IOC.id)).group_by(IOC.source).all()
    )
    avg_confidence = db.query(func.avg(IOC.confidence)).scalar() or 0
    total_sightings = db.query(func.count(IOCSighting.id)).scalar() or 0
    total_relationships = db.query(func.count(IOCRelationship.id)).scalar() or 0

    return {
        "total": total,
        "by_type": by_type,
        "by_state": by_state,
        "by_tlp": by_tlp,
        "by_source": by_source,
        "avg_confidence": round(float(avg_confidence), 1),
        "total_sightings": total_sightings,
        "total_relationships": total_relationships,
    }


# ═══════════════════════════════════════════════════════════════════════════
# Helpers
# ═══════════════════════════════════════════════════════════════════════════

def ioc_to_dict(ioc: IOC) -> dict[str, Any]:
    """Serialize an IOC model to dict."""
    tags = []
    if ioc.tags_json:
        try:
            tags = json.loads(ioc.tags_json)
        except Exception as exc:
            logger.warning("Malformed tags_json on IOC %s: %s", ioc.id, exc)
    mitre = []
    if ioc.mitre_techniques_json:
        try:
            mitre = json.loads(ioc.mitre_techniques_json)
        except Exception as exc:
            logger.warning("Malformed mitre_techniques_json on IOC %s: %s", ioc.id, exc)
    meta = {}
    if ioc.metadata_json:
        try:
            meta = json.loads(ioc.metadata_json)
        except Exception as exc:
            logger.warning("Malformed metadata_json on IOC %s: %s", ioc.id, exc)

    return {
        "id": ioc.id,
        "type": ioc.type,
        "value": ioc.value,
        "state": ioc.state,
        "confidence": ioc.confidence,
        "tlp": ioc.tlp,
        "source": ioc.source,
        "tags": tags,
        "mitre_techniques": mitre,
        "kill_chain_phase": ioc.kill_chain_phase,
        "metadata": meta,
        "stix_id": ioc.stix_id,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "expiry": ioc.expiry.isoformat() if ioc.expiry else None,
        "created_at": ioc.created_at.isoformat() if ioc.created_at else None,
        "updated_at": ioc.updated_at.isoformat() if ioc.updated_at else None,
    }
