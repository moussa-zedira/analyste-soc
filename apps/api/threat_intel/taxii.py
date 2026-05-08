"""TAXII 2.1 Client & Server — consommation et publication de STIX via le protocole TAXII.

Client: interroge des serveurs TAXII 2.1 externes.
Server: expose nos collections STIX pour que d'autres systemes puissent tirer nos IOC.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime
from typing import Any

import httpx
from fastapi import APIRouter, Depends, HTTPException, Query, Request
from fastapi.responses import JSONResponse
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.models.ioc import STIXCollection, STIXObject
from apps.api.security import require_api_key
from apps.api.threat_intel.observability import (
    CircuitOpenError,
    get_circuit_breaker,
    instrument,
)
from apps.api.threat_intel.stix import make_bundle, parse_bundle

logger = logging.getLogger(__name__)

TAXII_CONTENT_TYPE = "application/taxii+json;version=2.1"


# ═══════════════════════════════════════════════════════════════════════════
# TAXII 2.1 CLIENT
# ═══════════════════════════════════════════════════════════════════════════

class TAXIIClient:
    """Client TAXII 2.1 asynchrone."""

    def __init__(
        self,
        server_url: str,
        auth_type: str = "none",
        username: str | None = None,
        password: str | None = None,
        api_key: str | None = None,
        api_key_header: str = "Authorization",
        verify_ssl: bool = True,
        timeout: float = 30.0,
    ):
        self.server_url = server_url.rstrip("/")
        self.auth_type = auth_type
        self.username = username
        self.password = password
        self.api_key = api_key
        self.api_key_header = api_key_header
        self.verify_ssl = verify_ssl
        self.timeout = timeout
        self._cb = get_circuit_breaker("taxii")

    def _build_headers(self) -> dict[str, str]:
        headers: dict[str, str] = {
            "Accept": TAXII_CONTENT_TYPE,
            "Content-Type": TAXII_CONTENT_TYPE,
        }
        if self.auth_type == "api_key" and self.api_key:
            headers[self.api_key_header] = self.api_key
        return headers

    def _build_auth(self) -> httpx.BasicAuth | None:
        if self.auth_type == "basic" and self.username and self.password:
            return httpx.BasicAuth(self.username, self.password)
        return None

    @instrument("taxii", "get")
    async def _get(self, url: str, params: dict | None = None) -> dict | list | None:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
                resp = await self._cb.call(
                    client.get,
                    url, headers=self._build_headers(), auth=self._build_auth(), params=params,
                )
                if resp.status_code == 200:
                    return resp.json()
                logger.warning("TAXII GET %s -> %d: %s", url, resp.status_code, resp.text[:200])
                return None
        except CircuitOpenError:
            logger.warning("TAXII circuit open, skipping GET %s", url)
            return None

    @instrument("taxii", "post")
    async def _post(self, url: str, data: dict) -> dict | None:
        try:
            async with httpx.AsyncClient(verify=self.verify_ssl, timeout=self.timeout) as client:
                resp = await self._cb.call(
                    client.post,
                    url,
                    headers=self._build_headers(),
                    auth=self._build_auth(),
                    content=json.dumps(data),
                )
                if resp.status_code in (200, 201, 202):
                    return resp.json()
                logger.warning("TAXII POST %s -> %d: %s", url, resp.status_code, resp.text[:200])
                return None
        except CircuitOpenError:
            logger.warning("TAXII circuit open, skipping POST %s", url)
            return None

    # ── Discovery ──

    async def discover(self) -> dict | None:
        """GET /taxii2/ — server discovery."""
        return await self._get(f"{self.server_url}/taxii2/")

    # ── API Roots ──

    async def get_api_root(self, api_root: str | None = None) -> dict | None:
        """GET api root information."""
        if api_root:
            url = api_root.rstrip("/") + "/"
        else:
            disc = await self.discover()
            if not disc:
                return None
            roots = disc.get("api_roots", [])
            if not roots:
                return None
            url = roots[0]
        return await self._get(url)

    # ── Collections ──

    async def get_collections(self, api_root: str | None = None) -> list[dict]:
        """List collections available at an API root."""
        root = api_root or f"{self.server_url}/taxii2/api"
        data = await self._get(f"{root.rstrip('/')}/collections/")
        if data and isinstance(data, dict):
            return data.get("collections", [])
        return []

    async def get_collection(self, collection_id: str, api_root: str | None = None) -> dict | None:
        root = api_root or f"{self.server_url}/taxii2/api"
        return await self._get(f"{root.rstrip('/')}/collections/{collection_id}/")

    # ── Objects ──

    async def get_objects(
        self,
        collection_id: str,
        api_root: str | None = None,
        added_after: str | None = None,
        stix_type: str | None = None,
        stix_id: str | None = None,
        spec_version: str | None = None,
        limit: int | None = None,
        next_token: str | None = None,
    ) -> dict | None:
        """GET objects from a collection with optional filters."""
        root = api_root or f"{self.server_url}/taxii2/api"
        url = f"{root.rstrip('/')}/collections/{collection_id}/objects/"
        params: dict[str, Any] = {}
        if added_after:
            params["added_after"] = added_after
        if stix_type:
            params["match[type]"] = stix_type
        if stix_id:
            params["match[id]"] = stix_id
        if spec_version:
            params["match[spec_version]"] = spec_version
        if limit:
            params["limit"] = limit
        if next_token:
            params["next"] = next_token
        return await self._get(url, params=params)

    async def add_objects(
        self,
        collection_id: str,
        objects: list[dict],
        api_root: str | None = None,
    ) -> dict | None:
        """POST objects to a collection."""
        root = api_root or f"{self.server_url}/taxii2/api"
        url = f"{root.rstrip('/')}/collections/{collection_id}/objects/"
        envelope = make_bundle(objects)
        return await self._post(url, envelope)

    # ── Manifest ──

    async def get_manifest(
        self,
        collection_id: str,
        api_root: str | None = None,
        added_after: str | None = None,
        limit: int | None = None,
    ) -> dict | None:
        root = api_root or f"{self.server_url}/taxii2/api"
        url = f"{root.rstrip('/')}/collections/{collection_id}/manifest/"
        params: dict[str, Any] = {}
        if added_after:
            params["added_after"] = added_after
        if limit:
            params["limit"] = limit
        return await self._get(url, params=params)

    # ── Pagination helper ──

    async def get_all_objects(
        self,
        collection_id: str,
        api_root: str | None = None,
        added_after: str | None = None,
        stix_type: str | None = None,
        max_pages: int = 10,
    ) -> list[dict]:
        """Fetch all objects across pages."""
        all_objects: list[dict] = []
        next_token: str | None = None

        for _ in range(max_pages):
            result = await self.get_objects(
                collection_id=collection_id,
                api_root=api_root,
                added_after=added_after,
                stix_type=stix_type,
                limit=100,
                next_token=next_token,
            )
            if not result:
                break
            objects = result.get("objects", [])
            all_objects.extend(objects)
            more = result.get("more", False)
            next_token = result.get("next")
            if not more or not next_token:
                break

        return all_objects


# ═══════════════════════════════════════════════════════════════════════════
# TAXII 2.1 SERVER (FastAPI Router)
# ═══════════════════════════════════════════════════════════════════════════

router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1"])

# Helper to build TAXII JSON responses
def _taxii_response(data: Any, status_code: int = 200) -> JSONResponse:
    return JSONResponse(
        content=data,
        status_code=status_code,
        media_type=TAXII_CONTENT_TYPE,
    )


@router.get("/")
def taxii_discovery(request: Request) -> JSONResponse:
    """TAXII 2.1 Discovery endpoint."""
    base = str(request.base_url).rstrip("/")
    return _taxii_response({
        "title": "CyberDef TAXII Server",
        "description": "TAXII 2.1 server for the Cyber Defense Dashboard",
        "contact": "admin@cyberdef.local",
        "default": f"{base}/taxii2/api/",
        "api_roots": [f"{base}/taxii2/api/"],
    })


@router.get("/api/")
def taxii_api_root(request: Request) -> JSONResponse:
    """TAXII 2.1 API Root information."""
    return _taxii_response({
        "title": "CyberDef API Root",
        "description": "Primary API root for CyberDef threat intelligence",
        "versions": ["application/taxii+json;version=2.1"],
        "max_content_length": 10485760,
    })


@router.get("/api/collections/")
def taxii_list_collections(db: Session = Depends(get_db)) -> JSONResponse:
    """List all TAXII collections."""
    cols = db.query(STIXCollection).all()
    collections = []
    for c in cols:
        media = ["application/taxii+json;version=2.1"]
        if c.media_types_json:
            try:
                media = json.loads(c.media_types_json)
            except Exception as exc:
                logger.warning("Failed to parse media_types_json for collection %s: %s", c.collection_id, exc)
        collections.append({
            "id": c.collection_id,
            "title": c.title,
            "description": c.description or "",
            "can_read": c.can_read,
            "can_write": c.can_write,
            "media_types": media,
        })
    return _taxii_response({"collections": collections})


@router.get("/api/collections/{collection_id}/")
def taxii_get_collection(collection_id: str, db: Session = Depends(get_db)) -> JSONResponse:
    """Get a single collection by ID."""
    col = db.query(STIXCollection).filter(STIXCollection.collection_id == collection_id).first()
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")
    media = ["application/taxii+json;version=2.1"]
    if col.media_types_json:
        try:
            media = json.loads(col.media_types_json)
        except Exception as exc:
            logger.warning("Failed to parse media_types_json for collection %s: %s", col.collection_id, exc)
    return _taxii_response({
        "id": col.collection_id,
        "title": col.title,
        "description": col.description or "",
        "can_read": col.can_read,
        "can_write": col.can_write,
        "media_types": media,
    })


@router.get("/api/collections/{collection_id}/objects/")
def taxii_get_objects(
    collection_id: str,
    added_after: str | None = Query(None),
    limit: int = Query(100, le=1000),
    next: int = Query(0, alias="next"),
    db: Session = Depends(get_db),
    # match filters
    type: str | None = Query(None, alias="match[type]"),
    id: str | None = Query(None, alias="match[id]"),
    spec_version: str | None = Query(None, alias="match[spec_version]"),
) -> JSONResponse:
    """Get STIX objects from a collection."""
    col = db.query(STIXCollection).filter(STIXCollection.collection_id == collection_id).first()
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")
    if not col.can_read:
        raise HTTPException(status_code=403, detail="Collection is not readable")

    q = db.query(STIXObject).filter(STIXObject.collection_id == collection_id)

    if added_after:
        try:
            dt = datetime.fromisoformat(added_after.replace("Z", "+00:00"))
            q = q.filter(STIXObject.added > dt)
        except Exception as exc:
            logger.warning("Invalid added_after filter %r in taxii_get_objects: %s", added_after, exc)
    if type:
        q = q.filter(STIXObject.stix_type == type)
    if id:
        q = q.filter(STIXObject.stix_id == id)
    if spec_version:
        q = q.filter(STIXObject.spec_version == spec_version)

    total = q.count()
    objects_db = q.order_by(STIXObject.added).offset(next).limit(limit).all()

    objects = []
    for o in objects_db:
        try:
            objects.append(json.loads(o.object_json))
        except Exception as exc:
            logger.warning("Skipping malformed STIX object %s: %s", o.stix_id, exc)

    more = (next + limit) < total
    resp: dict[str, Any] = {"objects": objects, "more": more}
    if more:
        resp["next"] = str(next + limit)

    return _taxii_response(resp)


@router.post("/api/collections/{collection_id}/objects/")
def taxii_add_objects(
    collection_id: str,
    request_body: dict,
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Add STIX objects to a collection."""
    col = db.query(STIXCollection).filter(STIXCollection.collection_id == collection_id).first()
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")
    if not col.can_write:
        raise HTTPException(status_code=403, detail="Collection is not writable")

    try:
        stix_objects = parse_bundle(request_body)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid STIX bundle: {e}")

    successes = []
    failures = []

    for obj in stix_objects:
        stix_id = obj.get("id", "")
        stix_type = obj.get("type", "unknown")
        try:
            # Upsert: replace if same stix_id exists
            existing = db.query(STIXObject).filter(
                STIXObject.collection_id == collection_id,
                STIXObject.stix_id == stix_id,
            ).first()
            if existing:
                existing.object_json = json.dumps(obj, default=str)
                existing.stix_version = obj.get("modified")
                existing.added = datetime.now(UTC)
            else:
                db.add(STIXObject(
                    collection_id=collection_id,
                    stix_id=stix_id,
                    stix_type=stix_type,
                    spec_version=obj.get("spec_version", "2.1"),
                    stix_version=obj.get("modified"),
                    object_json=json.dumps(obj, default=str),
                ))
            successes.append(stix_id)
        except Exception as e:
            failures.append({"id": stix_id, "message": str(e)})

    db.commit()

    return _taxii_response({
        "id": f"status--{collection_id}",
        "status": "complete",
        "total_count": len(stix_objects),
        "success_count": len(successes),
        "failure_count": len(failures),
        "successes": [{"id": s} for s in successes],
        "failures": failures,
    }, status_code=202)


@router.get("/api/collections/{collection_id}/manifest/")
def taxii_manifest(
    collection_id: str,
    added_after: str | None = Query(None),
    limit: int = Query(100, le=1000),
    next: int = Query(0, alias="next"),
    db: Session = Depends(get_db),
) -> JSONResponse:
    """Get manifest (list of object ids + metadata) from a collection."""
    col = db.query(STIXCollection).filter(STIXCollection.collection_id == collection_id).first()
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")

    q = db.query(STIXObject).filter(STIXObject.collection_id == collection_id)
    if added_after:
        try:
            dt = datetime.fromisoformat(added_after.replace("Z", "+00:00"))
            q = q.filter(STIXObject.added > dt)
        except Exception as exc:
            logger.warning("Invalid added_after filter %r in taxii_manifest: %s", added_after, exc)

    total = q.count()
    items = q.order_by(STIXObject.added).offset(next).limit(limit).all()

    entries = []
    for o in items:
        entries.append({
            "id": o.stix_id,
            "date_added": o.added.isoformat() if o.added else None,
            "version": o.stix_version or o.spec_version,
            "media_type": TAXII_CONTENT_TYPE,
        })

    more = (next + limit) < total
    resp: dict[str, Any] = {"objects": entries, "more": more}
    if more:
        resp["next"] = str(next + limit)
    return _taxii_response(resp)


@router.delete("/api/collections/{collection_id}/objects/{object_id}/")
def taxii_delete_object(
    collection_id: str,
    object_id: str,
    db: Session = Depends(get_db),
    _auth: None = Depends(require_api_key),
) -> JSONResponse:
    """Delete a STIX object from a collection (requires auth)."""
    col = db.query(STIXCollection).filter(STIXCollection.collection_id == collection_id).first()
    if not col:
        raise HTTPException(status_code=404, detail="Collection not found")

    obj = db.query(STIXObject).filter(
        STIXObject.collection_id == collection_id,
        STIXObject.stix_id == object_id,
    ).first()
    if not obj:
        raise HTTPException(status_code=404, detail="Object not found")

    db.delete(obj)
    db.commit()
    return _taxii_response({"status": "deleted", "id": object_id})
