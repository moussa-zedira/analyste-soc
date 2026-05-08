"""Threat Feed Management — polling, import, health monitoring.

Gere les sources de flux de menaces: TAXII 2.1, fichiers STIX, CSV, MISP, plain text.
Inclut des feeds gratuits preconfigures (abuse.ch, ET, Tor, Feodo, PhishTank, OTX).
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from sqlalchemy.orm import Session

from apps.api.models.ioc import ThreatFeed
from apps.api.threat_intel.ioc_manager import (
    bulk_import_stix,
    create_ioc,
)
from apps.api.threat_intel.observability import (
    get_circuit_breaker,
    instrument,
)
from apps.api.threat_intel.taxii import TAXIIClient

logger = logging.getLogger(__name__)

# Circuit breaker partage pour l'ensemble des polls de feeds.
_FEED_CB = get_circuit_breaker("feed_manager")

# ---------------------------------------------------------------------------
# Built-in free feeds
# ---------------------------------------------------------------------------

BUILTIN_FEEDS: list[dict[str, Any]] = [
    {
        "name": "abuse.ch URLhaus (URLs)",
        "url": "https://urlhaus.abuse.ch/downloads/csv_online/",
        "feed_type": "csv_url",
        "interval_minutes": 60,
        "default_confidence": 80,
        "default_tlp": "WHITE",
        "config": {"ioc_type": "url", "csv_column": 2, "comment_char": "#", "skip_header": 9},
    },
    {
        "name": "abuse.ch MalwareBazaar (SHA256)",
        "url": "https://bazaar.abuse.ch/export/txt/sha256/recent/",
        "feed_type": "plaintext",
        "interval_minutes": 120,
        "default_confidence": 90,
        "default_tlp": "WHITE",
        "config": {"ioc_type": "hash_sha256"},
    },
    {
        "name": "abuse.ch ThreatFox (IOCs)",
        "url": "https://threatfox.abuse.ch/export/json/recent/",
        "feed_type": "threatfox_json",
        "interval_minutes": 60,
        "default_confidence": 85,
        "default_tlp": "WHITE",
        "config": {},
    },
    {
        "name": "Emerging Threats Compromised IPs",
        "url": "https://rules.emergingthreats.net/blockrules/compromised-ips.txt",
        "feed_type": "plaintext",
        "interval_minutes": 360,
        "default_confidence": 70,
        "default_tlp": "WHITE",
        "config": {"ioc_type": "ip"},
    },
    {
        "name": "Tor Exit Nodes",
        "url": "https://check.torproject.org/torbulkexitlist",
        "feed_type": "plaintext",
        "interval_minutes": 720,
        "default_confidence": 95,
        "default_tlp": "WHITE",
        "config": {"ioc_type": "ip", "tags": ["tor", "exit-node"]},
    },
    {
        "name": "Feodo Tracker C2 IPs",
        "url": "https://feodotracker.abuse.ch/downloads/ipblocklist.txt",
        "feed_type": "plaintext",
        "interval_minutes": 60,
        "default_confidence": 90,
        "default_tlp": "WHITE",
        "config": {"ioc_type": "ip", "tags": ["c2", "botnet"]},
    },
    {
        "name": "PhishTank (URLs)",
        "url": "http://data.phishtank.com/data/online-valid.csv",
        "feed_type": "csv_url",
        "interval_minutes": 360,
        "default_confidence": 80,
        "default_tlp": "WHITE",
        "config": {"ioc_type": "url", "csv_column": 1, "skip_header": 1},
    },
    {
        "name": "AlienVault OTX Pulse Subscriptions",
        "url": "https://otx.alienvault.com/api/v1/pulses/subscribed",
        "feed_type": "otx_pulse",
        "interval_minutes": 120,
        "default_confidence": 75,
        "default_tlp": "AMBER",
        "config": {"requires_api_key": True},
    },
]


# ═══════════════════════════════════════════════════════════════════════════
# Feed CRUD
# ═══════════════════════════════════════════════════════════════════════════

def create_feed(
    db: Session,
    name: str,
    url: str,
    feed_type: str,
    interval_minutes: int = 60,
    enabled: bool = True,
    auth_type: str | None = None,
    auth_config: dict | None = None,
    default_tlp: str = "AMBER",
    default_confidence: int = 50,
    config: dict | None = None,
) -> ThreatFeed:
    feed = ThreatFeed(
        name=name,
        url=url,
        feed_type=feed_type,
        interval_minutes=interval_minutes,
        enabled=enabled,
        auth_type=auth_type,
        auth_config_json=json.dumps(auth_config) if auth_config else None,
        default_tlp=default_tlp,
        default_confidence=default_confidence,
        config_json=json.dumps(config) if config else None,
    )
    db.add(feed)
    db.commit()
    db.refresh(feed)
    return feed


def get_feed(db: Session, feed_id: int) -> ThreatFeed | None:
    return db.get(ThreatFeed, feed_id)


def list_feeds(db: Session) -> list[ThreatFeed]:
    return db.query(ThreatFeed).order_by(ThreatFeed.name).all()


def update_feed(db: Session, feed_id: int, **kwargs: Any) -> ThreatFeed | None:
    feed = db.get(ThreatFeed, feed_id)
    if not feed:
        return None
    for key, val in kwargs.items():
        if key == "auth_config" and isinstance(val, dict):
            feed.auth_config_json = json.dumps(val)
        elif key == "config" and isinstance(val, dict):
            feed.config_json = json.dumps(val)
        elif hasattr(feed, key):
            setattr(feed, key, val)
    db.commit()
    db.refresh(feed)
    return feed


def delete_feed(db: Session, feed_id: int) -> bool:
    feed = db.get(ThreatFeed, feed_id)
    if not feed:
        return False
    db.delete(feed)
    db.commit()
    return True


# ═══════════════════════════════════════════════════════════════════════════
# Feed polling
# ═══════════════════════════════════════════════════════════════════════════

@instrument("feed_manager", "poll_feed")
async def poll_feed(db: Session, feed_id: int) -> dict:
    """Poll a feed and import new IOCs. Returns import stats."""
    feed = db.get(ThreatFeed, feed_id)
    if not feed:
        return {"error": "Feed not found"}

    feed.last_poll = datetime.now(UTC)
    db.commit()

    try:
        config = json.loads(feed.config_json) if feed.config_json else {}
        auth_config = json.loads(feed.auth_config_json) if feed.auth_config_json else {}

        if feed.feed_type == "taxii":
            stats = await _poll_taxii(db, feed, config, auth_config)
        elif feed.feed_type == "stix_url":
            stats = await _poll_stix_url(db, feed, config)
        elif feed.feed_type == "csv_url":
            stats = await _poll_csv_url(db, feed, config)
        elif feed.feed_type == "plaintext":
            stats = await _poll_plaintext(db, feed, config)
        elif feed.feed_type == "threatfox_json":
            stats = await _poll_threatfox(db, feed, config)
        elif feed.feed_type == "otx_pulse":
            stats = await _poll_otx_pulse(db, feed, config, auth_config)
        elif feed.feed_type == "misp":
            stats = await _poll_misp(db, feed, config, auth_config)
        else:
            stats = {"error": f"Unknown feed type: {feed.feed_type}"}

        if "error" not in stats:
            feed.last_success = datetime.now(UTC)
            feed.last_error = None
            new_count = stats.get("created", 0) + stats.get("updated", 0)
            feed.ioc_count = (feed.ioc_count or 0) + new_count
        else:
            feed.last_error = stats["error"]

        db.commit()
        return stats

    except Exception as e:
        feed.last_error = str(e)
        db.commit()
        logger.exception("Feed poll failed for %s", feed.name)
        return {"error": str(e)}


async def _poll_taxii(db: Session, feed: ThreatFeed, config: dict, auth_config: dict) -> dict:
    """Poll a TAXII 2.1 collection."""
    client = TAXIIClient(
        server_url=feed.url,
        auth_type=feed.auth_type or "none",
        username=auth_config.get("username"),
        password=auth_config.get("password"),
        api_key=auth_config.get("api_key"),
    )

    collection_id = config.get("collection_id")
    if not collection_id:
        collections = await client.get_collections()
        if not collections:
            return {"error": "No collections found"}
        collection_id = collections[0].get("id")

    added_after = None
    if feed.last_success:
        added_after = feed.last_success.strftime("%Y-%m-%dT%H:%M:%S.000Z")

    objects = await client.get_all_objects(
        collection_id=collection_id,
        added_after=added_after,
        stix_type="indicator",
    )

    if not objects:
        return {"created": 0, "updated": 0, "skipped": 0, "total": 0}

    bundle = {"type": "bundle", "objects": objects}
    return bulk_import_stix(db, bundle, source=feed.name)


async def _poll_stix_url(db: Session, feed: ThreatFeed, config: dict) -> dict:
    """Download a STIX bundle from URL."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await _FEED_CB.call(client.get, feed.url)
        resp.raise_for_status()
        data = resp.json()

    return bulk_import_stix(db, data, source=feed.name)


async def _poll_csv_url(db: Session, feed: ThreatFeed, config: dict) -> dict:
    """Download CSV and import IOCs."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await _FEED_CB.call(client.get, feed.url)
        resp.raise_for_status()
        text = resp.text

    ioc_type = config.get("ioc_type", "url")
    csv_column = config.get("csv_column")
    skip_header = config.get("skip_header", 0)
    comment_char = config.get("comment_char", "#")

    lines = text.splitlines()
    created = 0
    skipped = 0

    for i, line in enumerate(lines):
        if i < skip_header:
            continue
        line = line.strip()
        if not line or line.startswith(comment_char):
            continue

        if csv_column is not None:
            parts = line.split(",")
            if csv_column < len(parts):
                value = parts[csv_column].strip().strip('"')
            else:
                continue
        else:
            value = line

        if not value:
            continue

        tags = config.get("tags", [])
        try:
            create_ioc(
                db,
                ioc_type=ioc_type,
                value=value,
                source=feed.name,
                confidence=feed.default_confidence,
                tlp=feed.default_tlp,
                tags=tags,
            )
            created += 1
        except Exception:
            skipped += 1

    return {"created": created, "skipped": skipped}


async def _poll_plaintext(db: Session, feed: ThreatFeed, config: dict) -> dict:
    """Download a plain text list (one IOC per line)."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await _FEED_CB.call(client.get, feed.url)
        resp.raise_for_status()
        text = resp.text

    ioc_type = config.get("ioc_type", "ip")
    tags = config.get("tags", [])
    created = 0
    skipped = 0

    for line in text.splitlines():
        val = line.strip()
        if not val or val.startswith("#"):
            continue
        try:
            create_ioc(
                db,
                ioc_type=ioc_type,
                value=val,
                source=feed.name,
                confidence=feed.default_confidence,
                tlp=feed.default_tlp,
                tags=tags,
            )
            created += 1
        except Exception:
            skipped += 1

    return {"created": created, "skipped": skipped}


async def _poll_threatfox(db: Session, feed: ThreatFeed, config: dict) -> dict:
    """Poll ThreatFox JSON API."""
    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await _FEED_CB.call(
            client.post,
            "https://threatfox-api.abuse.ch/api/v1/",
            json={"query": "get_iocs", "days": 1},
        )
        resp.raise_for_status()
        data = resp.json()

    iocs = data.get("data", [])
    if not isinstance(iocs, list):
        return {"created": 0, "skipped": 0}

    created = 0
    skipped = 0

    TYPE_MAP = {
        "ip:port": "ip",
        "domain": "domain",
        "url": "url",
        "md5_hash": "hash_md5",
        "sha256_hash": "hash_sha256",
        "sha1_hash": "hash_sha1",
    }

    for entry in iocs:
        ioc_type_raw = entry.get("ioc_type", "")
        ioc_type = TYPE_MAP.get(ioc_type_raw)
        value = entry.get("ioc", "")

        if not ioc_type or not value:
            skipped += 1
            continue

        # Strip port from ip:port
        if ioc_type == "ip" and ":" in value:
            value = value.split(":")[0]

        tags = []
        if entry.get("malware"):
            tags.append(entry["malware"])
        if entry.get("tags"):
            tags.extend(entry["tags"] if isinstance(entry["tags"], list) else [])

        try:
            create_ioc(
                db,
                ioc_type=ioc_type,
                value=value,
                source=feed.name,
                confidence=entry.get("confidence_level", feed.default_confidence),
                tlp=feed.default_tlp,
                tags=tags,
            )
            created += 1
        except Exception:
            skipped += 1

    return {"created": created, "skipped": skipped}


async def _poll_otx_pulse(db: Session, feed: ThreatFeed, config: dict, auth_config: dict) -> dict:
    """Poll AlienVault OTX pulse subscriptions."""
    api_key = auth_config.get("api_key", "")
    if not api_key:
        return {"error": "OTX API key required"}

    async with httpx.AsyncClient(timeout=60.0) as client:
        resp = await _FEED_CB.call(
            client.get,
            "https://otx.alienvault.com/api/v1/pulses/subscribed?limit=10",
            headers={"X-OTX-API-KEY": api_key},
        )
        resp.raise_for_status()
        data = resp.json()

    pulses = data.get("results", [])
    created = 0
    skipped = 0

    OTX_TYPE_MAP = {
        "IPv4": "ip",
        "IPv6": "ip",
        "domain": "domain",
        "hostname": "domain",
        "URL": "url",
        "FileHash-MD5": "hash_md5",
        "FileHash-SHA1": "hash_sha1",
        "FileHash-SHA256": "hash_sha256",
        "email": "email",
        "CVE": "cve",
        "Mutex": "mutex",
        "CIDR": "cidr",
    }

    for pulse in pulses:
        pulse_tags = pulse.get("tags", [])
        for indicator in pulse.get("indicators", []):
            ioc_type = OTX_TYPE_MAP.get(indicator.get("type"))
            value = indicator.get("indicator", "")
            if not ioc_type or not value:
                skipped += 1
                continue
            try:
                create_ioc(
                    db,
                    ioc_type=ioc_type,
                    value=value,
                    source=feed.name,
                    confidence=feed.default_confidence,
                    tlp=feed.default_tlp,
                    tags=pulse_tags,
                )
                created += 1
            except Exception:
                skipped += 1

    return {"created": created, "skipped": skipped}


async def _poll_misp(db: Session, feed: ThreatFeed, config: dict, auth_config: dict) -> dict:
    """Poll a MISP feed."""
    api_key = auth_config.get("api_key", "")
    if not api_key:
        return {"error": "MISP API key required"}

    async with httpx.AsyncClient(timeout=60.0, verify=config.get("verify_ssl", True)) as client:
        resp = await _FEED_CB.call(
            client.get,
            f"{feed.url.rstrip('/')}/events/restSearch",
            headers={
                "Authorization": api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            },
            params={"limit": 50, "published": True},
        )
        resp.raise_for_status()
        data = resp.json()

    events = data.get("response", [])
    created = 0
    skipped = 0

    MISP_TYPE_MAP = {
        "ip-src": "ip", "ip-dst": "ip",
        "domain": "domain", "hostname": "domain",
        "url": "url",
        "md5": "hash_md5", "sha1": "hash_sha1", "sha256": "hash_sha256",
        "email-src": "email", "email-dst": "email",
        "filename": "filename", "mutex": "mutex",
    }

    for event_wrapper in events:
        event = event_wrapper.get("Event", event_wrapper)
        event_tags = [t.get("name", "") for t in event.get("Tag", [])]
        for attr in event.get("Attribute", []):
            ioc_type = MISP_TYPE_MAP.get(attr.get("type"))
            value = attr.get("value", "")
            if not ioc_type or not value:
                skipped += 1
                continue
            try:
                create_ioc(
                    db,
                    ioc_type=ioc_type,
                    value=value,
                    source=feed.name,
                    confidence=feed.default_confidence,
                    tlp=feed.default_tlp,
                    tags=event_tags,
                )
                created += 1
            except Exception:
                skipped += 1

    return {"created": created, "skipped": skipped}


# ═══════════════════════════════════════════════════════════════════════════
# Feed statistics
# ═══════════════════════════════════════════════════════════════════════════

def feed_to_dict(feed: ThreatFeed) -> dict[str, Any]:
    """Serialize a ThreatFeed model to dict."""
    config = {}
    if feed.config_json:
        try:
            config = json.loads(feed.config_json)
        except Exception as exc:
            logger.warning("Malformed config_json on feed %s: %s", feed.id, exc)
    return {
        "id": feed.id,
        "name": feed.name,
        "url": feed.url,
        "feed_type": feed.feed_type,
        "interval_minutes": feed.interval_minutes,
        "enabled": feed.enabled,
        "auth_type": feed.auth_type,
        "default_tlp": feed.default_tlp,
        "default_confidence": feed.default_confidence,
        "config": config,
        "last_poll": feed.last_poll.isoformat() if feed.last_poll else None,
        "last_success": feed.last_success.isoformat() if feed.last_success else None,
        "last_error": feed.last_error,
        "ioc_count": feed.ioc_count or 0,
        "created_at": feed.created_at.isoformat() if feed.created_at else None,
    }


def get_feed_stats(db: Session, feed_id: int) -> dict | None:
    """Get detailed stats for a feed."""
    feed = db.get(ThreatFeed, feed_id)
    if not feed:
        return None
    base = feed_to_dict(feed)
    # Health status
    if not feed.last_poll:
        base["health"] = "never_polled"
    elif feed.last_error:
        base["health"] = "error"
    elif feed.last_success:
        base["health"] = "healthy"
    else:
        base["health"] = "unknown"
    return base
