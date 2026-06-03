"""Threat Feed Management API."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.ioc import ThreatFeed
from apps.api.security import require_api_key
from apps.api.threat_intel.feed_manager import (
    BUILTIN_FEEDS,
    create_feed,
    delete_feed,
    get_feed_stats,
    list_feeds,
    poll_feed,
    update_feed,
)

router = APIRouter(prefix="/feeds", dependencies=[Depends(require_api_key)])


class FeedCreate(BaseModel):
    name: str
    url: str
    feed_type: str = Field("plaintext", description="taxii, stix_url, csv_url, misp, plaintext")
    interval_minutes: int = 60
    auth_type: str | None = None
    auth_config: dict[str, Any] | None = None
    default_tlp: str = "AMBER"
    default_confidence: int = 50
    config: dict[str, Any] | None = None


class FeedUpdate(BaseModel):
    name: str | None = None
    url: str | None = None
    feed_type: str | None = None
    interval_minutes: int | None = None
    enabled: bool | None = None
    auth_type: str | None = None
    auth_config: dict[str, Any] | None = None
    default_tlp: str | None = None
    default_confidence: int | None = None
    config: dict[str, Any] | None = None


def _feed_to_dict(f: ThreatFeed) -> dict:
    import json

    return {
        "id": f.id,
        "name": f.name,
        "url": f.url,
        "feed_type": f.feed_type,
        "interval_minutes": f.interval_minutes,
        "enabled": f.enabled,
        "auth_type": f.auth_type,
        "default_tlp": f.default_tlp,
        "default_confidence": f.default_confidence,
        "ioc_count": f.ioc_count,
        "last_poll": f.last_poll.isoformat() if f.last_poll else None,
        "last_success": f.last_success.isoformat() if f.last_success else None,
        "last_error": f.last_error,
        "config": json.loads(f.config_json) if f.config_json else {},
    }


@router.get("")
def list_all(db: Session = Depends(get_db)):
    feeds = list_feeds(db)
    return {"feeds": [_feed_to_dict(f) for f in feeds]}


@router.get("/builtin")
def builtin():
    return {"feeds": BUILTIN_FEEDS}


@router.post("")
def create(body: FeedCreate, db: Session = Depends(get_db)):
    feed = create_feed(db, **body.model_dump())
    return {"status": "created", "feed": _feed_to_dict(feed)}


@router.put("/{feed_id}")
def update(feed_id: int, body: FeedUpdate, db: Session = Depends(get_db)):
    feed = update_feed(db, feed_id, **body.model_dump(exclude_none=True))
    if not feed:
        raise HTTPException(404, "Feed not found")
    return {"status": "updated", "feed": _feed_to_dict(feed)}


@router.delete("/{feed_id}")
def delete(feed_id: int, db: Session = Depends(get_db)):
    ok = delete_feed(db, feed_id)
    if not ok:
        raise HTTPException(404, "Feed not found")
    return {"status": "deleted"}


@router.post("/{feed_id}/poll")
async def trigger_poll(feed_id: int, db: Session = Depends(get_db)):
    feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found")
    try:
        result = await poll_feed(db, feed)
        return {"status": "polled", "result": result}
    except Exception as exc:
        raise HTTPException(500, f"Poll failed: {exc}")


@router.get("/{feed_id}/stats")
def stats(feed_id: int, db: Session = Depends(get_db)):
    feed = db.query(ThreatFeed).filter(ThreatFeed.id == feed_id).first()
    if not feed:
        raise HTTPException(404, "Feed not found")
    return get_feed_stats(db, feed)
