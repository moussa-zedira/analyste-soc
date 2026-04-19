"""IOC Management API — CRUD, bulk import/export, sightings, graph."""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.security import require_api_key
from apps.api.threat_intel.ioc_manager import (
    create_ioc,
    get_ioc,
    list_iocs,
    update_ioc,
    delete_ioc,
    revoke_ioc,
    mark_false_positive,
    get_sightings,
    get_related_iocs,
    bulk_import_stix,
    bulk_import_csv,
    bulk_import_text,
    export_stix_bundle,
    export_csv,
    get_ioc_stats,
    IOC_TYPES,
    IOC_STATES,
    TLP_LEVELS,
)

router = APIRouter(prefix="/ioc", dependencies=[Depends(require_api_key)])


# ── Schemas ──────────────────────────────────────────────────────────────────

class IOCCreate(BaseModel):
    type: str = Field(..., description="IOC type: ip, domain, url, hash_md5, etc.")
    value: str
    source: str = "manual"
    confidence: int = Field(50, ge=0, le=100)
    tlp: str = "AMBER"
    tags: list[str] | None = None
    mitre_techniques: list[str] | None = None
    kill_chain_phase: str | None = None
    metadata: dict[str, Any] | None = None
    ttl_hours: int | None = None
    enrich: bool = False


class IOCUpdate(BaseModel):
    state: str | None = None
    confidence: int | None = None
    tlp: str | None = None
    tags: list[str] | None = None
    mitre_techniques: list[str] | None = None
    kill_chain_phase: str | None = None
    metadata: dict[str, Any] | None = None


class BulkImport(BaseModel):
    format: str = Field("text", description="stix, csv, text")
    data: str = Field(..., description="Raw data to import")
    default_confidence: int = 50
    default_tlp: str = "AMBER"
    source: str = "bulk_import"


def _ioc_to_dict(ioc: Any) -> dict:
    return {
        "id": ioc.id,
        "type": ioc.type,
        "value": ioc.value,
        "state": ioc.state,
        "confidence": ioc.confidence,
        "tlp": ioc.tlp,
        "source": ioc.source,
        "tags": json.loads(ioc.tags_json) if ioc.tags_json else [],
        "mitre_techniques": json.loads(ioc.mitre_techniques_json) if ioc.mitre_techniques_json else [],
        "kill_chain_phase": ioc.kill_chain_phase,
        "metadata": json.loads(ioc.metadata_json) if ioc.metadata_json else {},
        "stix_id": ioc.stix_id,
        "first_seen": ioc.first_seen.isoformat() if ioc.first_seen else None,
        "last_seen": ioc.last_seen.isoformat() if ioc.last_seen else None,
        "expiry": ioc.expiry.isoformat() if ioc.expiry else None,
        "sightings_count": len(ioc.sightings) if hasattr(ioc, "sightings") and ioc.sightings else 0,
    }


# ── Endpoints ────────────────────────────────────────────────────────────────

@router.post("")
def create(body: IOCCreate, db: Session = Depends(get_db)):
    try:
        ioc = create_ioc(
            db, ioc_type=body.type, value=body.value, source=body.source,
            confidence=body.confidence, tlp=body.tlp, tags=body.tags,
            mitre_techniques=body.mitre_techniques, kill_chain_phase=body.kill_chain_phase,
            metadata=body.metadata, ttl_hours=body.ttl_hours, enrich=body.enrich,
        )
        return {"status": "created", "ioc": _ioc_to_dict(ioc)}
    except ValueError as exc:
        raise HTTPException(400, str(exc))


@router.get("")
def list_all(
    type: str | None = None,
    state: str | None = None,
    tlp: str | None = None,
    source: str | None = None,
    confidence_min: int | None = None,
    confidence_max: int | None = None,
    search: str | None = None,
    limit: int = Query(100, le=1000),
    offset: int = 0,
    db: Session = Depends(get_db),
):
    result = list_iocs(
        db, ioc_type=type, state=state, tlp=tlp, source=source,
        confidence_min=confidence_min, confidence_max=confidence_max,
        search=search, limit=limit, offset=offset,
    )
    # list_iocs peut renvoyer (items, total) ou directement items ;
    # on normalise pour supporter les deux variantes.
    if isinstance(result, tuple) and len(result) == 2:
        iocs, total = result
    else:
        iocs = list(result)
        total = len(iocs)
    return {"iocs": [_ioc_to_dict(i) for i in iocs], "count": total}


@router.get("/types")
def get_types():
    return {"types": sorted(IOC_TYPES), "states": sorted(IOC_STATES), "tlp_levels": sorted(TLP_LEVELS)}


@router.get("/stats")
def stats(db: Session = Depends(get_db)):
    return get_ioc_stats(db)


@router.get("/export/stix")
def export_stix(db: Session = Depends(get_db), state: str = "active"):
    bundle = export_stix_bundle(db, state=state)
    return bundle


@router.get("/export/csv")
def export_csv_endpoint(db: Session = Depends(get_db), state: str = "active"):
    csv_text = export_csv(db, state=state)
    return {"csv": csv_text}


@router.get("/graph")
def graph(db: Session = Depends(get_db), limit: int = 200):
    from apps.api.models.ioc import IOC, IOCRelationship
    iocs = db.query(IOC).filter(IOC.state == "active").limit(limit).all()
    ioc_ids = {i.id for i in iocs}
    rels = db.query(IOCRelationship).filter(
        IOCRelationship.source_ioc_id.in_(ioc_ids),
        IOCRelationship.target_ioc_id.in_(ioc_ids),
    ).all()
    nodes = [{"id": i.id, "type": i.type, "value": i.value, "confidence": i.confidence} for i in iocs]
    edges = [{"source": r.source_ioc_id, "target": r.target_ioc_id, "type": r.relationship_type} for r in rels]
    return {"nodes": nodes, "edges": edges}


@router.get("/{ioc_id}")
def detail(ioc_id: int, db: Session = Depends(get_db)):
    ioc = get_ioc(db, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return {"ioc": _ioc_to_dict(ioc)}


@router.put("/{ioc_id}")
def update(ioc_id: int, body: IOCUpdate, db: Session = Depends(get_db)):
    ioc = update_ioc(db, ioc_id, **body.model_dump(exclude_none=True))
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return {"status": "updated", "ioc": _ioc_to_dict(ioc)}


@router.delete("/{ioc_id}")
def delete(ioc_id: int, db: Session = Depends(get_db)):
    ok = delete_ioc(db, ioc_id)
    if not ok:
        raise HTTPException(404, "IOC not found")
    return {"status": "deleted"}


@router.post("/{ioc_id}/revoke")
def revoke(ioc_id: int, db: Session = Depends(get_db)):
    ioc = revoke_ioc(db, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return {"status": "revoked"}


@router.post("/{ioc_id}/false-positive")
def false_positive(ioc_id: int, db: Session = Depends(get_db)):
    ioc = mark_false_positive(db, ioc_id)
    if not ioc:
        raise HTTPException(404, "IOC not found")
    return {"status": "marked_false_positive"}


@router.get("/{ioc_id}/sightings")
def sightings(ioc_id: int, db: Session = Depends(get_db)):
    sights = get_sightings(db, ioc_id)
    return {"sightings": [
        {"id": s.id, "event_id": s.event_id, "source": s.source, "count": s.count,
         "timestamp": s.timestamp.isoformat() if s.timestamp else None}
        for s in sights
    ]}


@router.get("/{ioc_id}/related")
def related(ioc_id: int, db: Session = Depends(get_db)):
    related_iocs = get_related_iocs(db, ioc_id)
    return {"related": [_ioc_to_dict(r) for r in related_iocs]}


@router.post("/bulk")
def bulk(body: BulkImport, db: Session = Depends(get_db)):
    try:
        if body.format == "stix":
            count = bulk_import_stix(db, body.data, source=body.source,
                                     default_confidence=body.default_confidence, default_tlp=body.default_tlp)
        elif body.format == "csv":
            count = bulk_import_csv(db, body.data, source=body.source,
                                    default_confidence=body.default_confidence, default_tlp=body.default_tlp)
        else:
            count = bulk_import_text(db, body.data, source=body.source)
        return {"status": "imported", "count": count}
    except Exception as exc:
        raise HTTPException(400, str(exc))
