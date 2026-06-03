"""Routes /redteam/bloodhound (V4.5).

CRUD datasets + queries specialisees + pivot read-only depuis une session.

Aucune route ne declenche d'execution. Tout est lecture du graphe importe.
"""

from __future__ import annotations

import logging
from datetime import datetime

from fastapi import (
    APIRouter,
    Depends,
    File,
    Form,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.auth import get_current_user
from apps.api.db.session import get_db
from apps.api.models.bloodhound import BHDataset, BHNode
from apps.api.models.engagement import Engagement
from apps.api.models.sliver import SliverSession
from apps.api.models.user import User
from apps.api.pentest.bloodhound.importer import import_bloodhound_dump
from apps.api.pentest.bloodhound.pivot import (
    attack_paths_from_session,
    dataset_stats,
    list_asreproastable,
    list_high_value,
    list_kerberoastable,
    list_local_admins,
    list_logged_on_users,
    list_unconstrained_delegation,
    paths_to_high_value,
)

logger = logging.getLogger("apps.api.pentest.bloodhound")
router = APIRouter(prefix="/redteam/bloodhound", tags=["Red Team BloodHound"])


MAX_UPLOAD_BYTES = 200 * 1024 * 1024  # 200 MB


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class BHDatasetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    source_filename: str
    engagement_id: str | None
    bh_schema_version: int
    nodes_count: int
    edges_count: int
    uploaded_by: str | None
    uploaded_at: datetime
    notes: str = ""


class BHNodeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    sid: str
    object_type: str
    name: str
    domain: str
    high_value: bool
    props: dict | None = None


class PivotPayload(BaseModel):
    session_id: str | None = None
    hostname: str | None = None
    username: str | None = None
    max_hops: int = Field(default=5, ge=1, le=8)
    max_paths: int = Field(default=20, ge=1, le=100)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_out(d: BHDataset) -> BHDatasetOut:
    return BHDatasetOut(
        id=d.id,
        name=d.name,
        source_filename=d.source_filename or "",
        engagement_id=d.engagement_id,
        bh_schema_version=d.bh_schema_version,
        nodes_count=d.nodes_count,
        edges_count=d.edges_count,
        uploaded_by=d.uploaded_by,
        uploaded_at=d.uploaded_at,
        notes=d.notes or "",
    )


def _node_out(n: BHNode) -> BHNodeOut:
    return BHNodeOut(
        id=n.id,
        sid=n.sid,
        object_type=n.object_type,
        name=n.name,
        domain=n.domain,
        high_value=n.high_value,
        props=n.props or {},
    )


def _get_dataset_or_404(db: Session, dataset_id: str) -> BHDataset:
    ds = db.get(BHDataset, dataset_id)
    if ds is None:
        raise HTTPException(status_code=404, detail="Dataset not found")
    return ds


# ---------------------------------------------------------------------------
# CRUD datasets
# ---------------------------------------------------------------------------


@router.post(
    "/datasets",
    response_model=BHDatasetOut,
    status_code=status.HTTP_201_CREATED,
)
async def upload_dataset(
    file: UploadFile = File(...),
    name: str = Form(...),
    engagement_id: str | None = Form(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> BHDatasetOut:
    """Upload d'un zip BloodHound CE (v5)."""
    if engagement_id:
        eng = db.get(Engagement, engagement_id)
        if eng is None:
            raise HTTPException(status_code=400, detail="Unknown engagement_id")

    try:
        content = await file.read()
    except Exception as exc:  # noqa: BLE001
        logger.exception("Failed to read upload: %s", exc)
        raise HTTPException(status_code=400, detail="Cannot read upload")

    if not content:
        raise HTTPException(status_code=400, detail="Empty upload")
    if len(content) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"Upload too large (max {MAX_UPLOAD_BYTES} bytes)",
        )

    try:
        ds = import_bloodhound_dump(
            db,
            content=content,
            name=name,
            source_filename=file.filename or "",
            user_id=user.id,
            engagement_id=engagement_id,
        )
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001
        logger.exception("BloodHound import failed: %s", exc)
        raise HTTPException(status_code=500, detail="BloodHound import failed")

    return _to_out(ds)


@router.get("/datasets", response_model=list[BHDatasetOut])
def list_datasets(
    engagement_id: str | None = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[BHDatasetOut]:
    q = db.query(BHDataset)
    if engagement_id:
        q = q.filter(BHDataset.engagement_id == engagement_id)
    items = q.order_by(desc(BHDataset.uploaded_at)).offset(offset).limit(limit).all()
    return [_to_out(d) for d in items]


@router.get("/datasets/{dataset_id}")
def get_dataset(
    dataset_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    ds = _get_dataset_or_404(db, dataset_id)
    stats = dataset_stats(db, dataset_id)
    top_hv = list_high_value(db, dataset_id)[:10]
    return {
        "dataset": _to_out(ds).model_dump(mode="json"),
        "stats": stats,
        "top_high_value": top_hv,
    }


@router.delete("/datasets/{dataset_id}", status_code=204)
def delete_dataset(
    dataset_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    ds = _get_dataset_or_404(db, dataset_id)
    db.delete(ds)
    db.commit()
    logger.info("Dataset %s deleted by %s", dataset_id, user.id)


# ---------------------------------------------------------------------------
# Nodes
# ---------------------------------------------------------------------------


@router.get("/datasets/{dataset_id}/nodes", response_model=list[BHNodeOut])
def list_nodes(
    dataset_id: str,
    object_type: str | None = Query(None),
    high_value: bool | None = Query(None),
    name: str | None = Query(None),
    limit: int = Query(100, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[BHNodeOut]:
    _get_dataset_or_404(db, dataset_id)
    q = db.query(BHNode).filter(BHNode.dataset_id == dataset_id)
    if object_type:
        q = q.filter(BHNode.object_type == object_type)
    if high_value is not None:
        q = q.filter(BHNode.high_value.is_(high_value))
    if name:
        q = q.filter(BHNode.name.ilike(f"%{name}%"))
    items = q.order_by(BHNode.name).offset(offset).limit(limit).all()
    return [_node_out(n) for n in items]


@router.get("/datasets/{dataset_id}/kerberoastable")
def get_kerberoastable(
    dataset_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _get_dataset_or_404(db, dataset_id)
    return list_kerberoastable(db, dataset_id)


@router.get("/datasets/{dataset_id}/asreproastable")
def get_asreproastable(
    dataset_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _get_dataset_or_404(db, dataset_id)
    return list_asreproastable(db, dataset_id)


@router.get("/datasets/{dataset_id}/unconstrained-delegation")
def get_unconstrained_delegation(
    dataset_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _get_dataset_or_404(db, dataset_id)
    return list_unconstrained_delegation(db, dataset_id)


@router.get("/datasets/{dataset_id}/high-value-targets")
def get_high_value(
    dataset_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _get_dataset_or_404(db, dataset_id)
    return list_high_value(db, dataset_id)


# ---------------------------------------------------------------------------
# Host queries
# ---------------------------------------------------------------------------


@router.get("/datasets/{dataset_id}/host/{hostname}/local-admins")
def host_local_admins(
    dataset_id: str,
    hostname: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _get_dataset_or_404(db, dataset_id)
    return list_local_admins(db, dataset_id, hostname)


@router.get("/datasets/{dataset_id}/host/{hostname}/logged-users")
def host_logged_users(
    dataset_id: str,
    hostname: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[dict]:
    _get_dataset_or_404(db, dataset_id)
    return list_logged_on_users(db, dataset_id, hostname)


@router.get("/datasets/{dataset_id}/host/{hostname}/paths-to-high-value")
def host_paths_to_high_value(
    dataset_id: str,
    hostname: str,
    max_hops: int = Query(5, ge=1, le=8),
    max_paths: int = Query(20, ge=1, le=100),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _get_dataset_or_404(db, dataset_id)
    from apps.api.pentest.bloodhound.pivot import _find_node_by_hostname

    node = _find_node_by_hostname(db, dataset_id, hostname)
    if node is None:
        return {"host": None, "paths": []}
    paths = paths_to_high_value(db, dataset_id, node.sid, max_hops=max_hops, max_paths=max_paths)
    return {
        "host": {
            "sid": node.sid,
            "name": node.name,
            "object_type": node.object_type,
            "high_value": node.high_value,
        },
        "paths": paths,
    }


# ---------------------------------------------------------------------------
# Pivot from Sliver session (read-only synthese)
# ---------------------------------------------------------------------------


@router.post("/datasets/{dataset_id}/pivot-from-session")
def pivot_from_session(
    dataset_id: str,
    payload: PivotPayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    """Synthese pivot pour une session Sliver active. READ-ONLY."""
    _get_dataset_or_404(db, dataset_id)

    hostname = payload.hostname
    username = payload.username

    if payload.session_id and (not hostname or not username):
        sess = db.get(SliverSession, payload.session_id)
        if sess is None:
            raise HTTPException(status_code=404, detail="Sliver session not found")
        hostname = hostname or sess.hostname
        username = username or sess.username

    if not hostname:
        raise HTTPException(
            status_code=400,
            detail="hostname is required (or pass session_id)",
        )

    try:
        result = attack_paths_from_session(
            db,
            dataset_id,
            session_hostname=hostname,
            session_username=username,
            max_hops=payload.max_hops,
            max_paths=payload.max_paths,
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("pivot-from-session failed: %s", exc)
        raise HTTPException(status_code=500, detail="pivot computation failed")
    return result
