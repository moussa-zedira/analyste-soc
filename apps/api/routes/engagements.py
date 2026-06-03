"""Routes /redteam/engagements (V4.3b) — CRUD + members + kill-switch + audit."""

from __future__ import annotations

import logging
import os
import uuid
from datetime import UTC, datetime

from fastapi import (
    APIRouter,
    Depends,
    File,
    HTTPException,
    Query,
    UploadFile,
    status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.auth import get_current_user
from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.models.engagement import (
    Engagement,
    EngagementMember,
    OperatorAuditLog,
)
from apps.api.models.user import User
from apps.api.pentest.engagement.audit import (
    record_operator_action,
    verify_audit_entry,
)

logger = logging.getLogger("apps.api.pentest.engagement")
router = APIRouter(prefix="/redteam/engagements", tags=["Red Team Engagements"])


VALID_STATUS = ("draft", "active", "paused", "closed")
VALID_MEMBER_ROLES = ("lead", "operator", "observer")


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class EngagementCreate(BaseModel):
    name: str = Field(min_length=1, max_length=256)
    client_name: str = Field(min_length=1, max_length=256)
    scope_targets: list[str] = Field(default_factory=list)
    excluded_targets: list[str] = Field(default_factory=list)
    start_date: datetime | None = None
    end_date: datetime | None = None
    notes: str = ""
    mitre_tactics_authorized: list[str] = Field(default_factory=list)
    status: str = "draft"


class EngagementUpdate(BaseModel):
    name: str | None = None
    client_name: str | None = None
    scope_targets: list[str] | None = None
    excluded_targets: list[str] | None = None
    start_date: datetime | None = None
    end_date: datetime | None = None
    notes: str | None = None
    mitre_tactics_authorized: list[str] | None = None
    status: str | None = None


class EngagementOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    client_name: str
    status: str
    scope_targets: list[str] = []
    excluded_targets: list[str] = []
    start_date: datetime | None = None
    end_date: datetime | None = None
    roe_document_path: str | None = None
    kill_switch_active: bool
    created_by: str | None = None
    created_at: datetime
    notes: str = ""
    mitre_tactics_authorized: list[str] = []


class MemberAdd(BaseModel):
    user_id: str
    role: str = "operator"


class KillSwitchPayload(BaseModel):
    active: bool


class AuditEntryOut(BaseModel):
    id: str
    engagement_id: str | None
    user_id: str | None
    action_type: str
    target: str
    command: str
    result_summary: str
    timestamp: datetime
    signature: str
    in_scope: bool


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_out(eng: Engagement) -> EngagementOut:
    return EngagementOut(
        id=eng.id,
        name=eng.name,
        client_name=eng.client_name,
        status=eng.status,
        scope_targets=list(eng.scope_targets or []),
        excluded_targets=list(eng.excluded_targets or []),
        start_date=eng.start_date,
        end_date=eng.end_date,
        roe_document_path=eng.roe_document_path,
        kill_switch_active=eng.kill_switch_active,
        created_by=eng.created_by,
        created_at=eng.created_at,
        notes=eng.notes or "",
        mitre_tactics_authorized=list(eng.mitre_tactics_authorized or []),
    )


def _check_lead_or_admin(db: Session, user: User, engagement_id: str) -> None:
    """Autorise admin global, ou membre lead de l'engagement."""
    if user.role == "admin":
        return
    member = (
        db.query(EngagementMember)
        .filter(
            EngagementMember.engagement_id == engagement_id,
            EngagementMember.user_id == user.id,
        )
        .first()
    )
    if member is not None and member.role == "lead":
        return
    raise HTTPException(
        status_code=status.HTTP_403_FORBIDDEN,
        detail="Lead role on this engagement (or admin) required",
    )


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------


@router.post("", response_model=EngagementOut, status_code=status.HTTP_201_CREATED)
def create_engagement(
    payload: EngagementCreate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EngagementOut:
    if user.role not in ("admin", "lead"):
        raise HTTPException(status_code=403, detail="admin or lead role required")
    if payload.status not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")

    eng_id = str(uuid.uuid4())
    eng = Engagement(
        id=eng_id,
        name=payload.name,
        client_name=payload.client_name,
        status=payload.status,
        scope_targets=list(payload.scope_targets or []),
        excluded_targets=list(payload.excluded_targets or []),
        start_date=payload.start_date,
        end_date=payload.end_date,
        kill_switch_active=False,
        created_by=user.id,
        created_at=datetime.now(UTC),
        notes=payload.notes or "",
        mitre_tactics_authorized=list(payload.mitre_tactics_authorized or []),
    )
    db.add(eng)
    # Le createur devient automatiquement lead
    db.add(
        EngagementMember(
            engagement_id=eng_id,
            user_id=user.id,
            role="lead",
            added_at=datetime.now(UTC),
        )
    )
    db.commit()
    db.refresh(eng)

    record_operator_action(
        db,
        engagement_id=eng_id,
        user_id=user.id,
        action_type="engagement_create",
        target=payload.client_name,
        command="POST /redteam/engagements",
        result_summary=f"name={payload.name}",
    )
    return _to_out(eng)


@router.get("", response_model=list[EngagementOut])
def list_engagements(
    status_filter: str | None = Query(None, alias="status"),
    client_name: str | None = None,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[EngagementOut]:
    q = db.query(Engagement)
    if status_filter:
        q = q.filter(Engagement.status == status_filter)
    if client_name:
        q = q.filter(Engagement.client_name.ilike(f"%{client_name}%"))
    items = q.order_by(desc(Engagement.created_at)).limit(500).all()
    return [_to_out(e) for e in items]


@router.get("/{engagement_id}")
def get_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    members = (
        db.query(EngagementMember).filter(EngagementMember.engagement_id == engagement_id).all()
    )
    last_logs = (
        db.query(OperatorAuditLog)
        .filter(OperatorAuditLog.engagement_id == engagement_id)
        .order_by(desc(OperatorAuditLog.timestamp))
        .limit(50)
        .all()
    )
    return {
        "engagement": _to_out(eng).model_dump(),
        "members": [
            {"user_id": m.user_id, "role": m.role, "added_at": m.added_at.isoformat()}
            for m in members
        ],
        "recent_audit_logs": [
            {
                "id": l.id,
                "action_type": l.action_type,
                "target": l.target,
                "in_scope": l.in_scope,
                "timestamp": l.timestamp.isoformat(),
                "user_id": l.user_id,
            }
            for l in last_logs
        ],
    }


@router.put("/{engagement_id}", response_model=EngagementOut)
def update_engagement(
    engagement_id: str,
    payload: EngagementUpdate,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> EngagementOut:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    _check_lead_or_admin(db, user, engagement_id)

    data = payload.model_dump(exclude_unset=True)
    if "status" in data and data["status"] not in VALID_STATUS:
        raise HTTPException(status_code=400, detail="Invalid status")
    for k, v in data.items():
        setattr(eng, k, v)
    db.add(eng)
    db.commit()
    db.refresh(eng)

    record_operator_action(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="engagement_update",
        target=eng.client_name,
        command="PUT /redteam/engagements/{id}",
        result_summary=f"fields={list(data.keys())}",
    )
    return _to_out(eng)


@router.post("/{engagement_id}/members", status_code=status.HTTP_201_CREATED)
def add_member(
    engagement_id: str,
    payload: MemberAdd,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    _check_lead_or_admin(db, user, engagement_id)
    if payload.role not in VALID_MEMBER_ROLES:
        raise HTTPException(status_code=400, detail="Invalid role")

    target_user = db.get(User, payload.user_id)
    if target_user is None:
        raise HTTPException(status_code=404, detail="User not found")

    existing = (
        db.query(EngagementMember)
        .filter(
            EngagementMember.engagement_id == engagement_id,
            EngagementMember.user_id == payload.user_id,
        )
        .first()
    )
    if existing is not None:
        existing.role = payload.role
        db.add(existing)
        db.commit()
        return {
            "engagement_id": engagement_id,
            "user_id": payload.user_id,
            "role": payload.role,
            "updated": True,
        }

    db.add(
        EngagementMember(
            engagement_id=engagement_id,
            user_id=payload.user_id,
            role=payload.role,
            added_at=datetime.now(UTC),
        )
    )
    db.commit()
    record_operator_action(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="engagement_member_add",
        target=payload.user_id,
        command="POST /members",
        result_summary=f"role={payload.role}",
    )
    return {
        "engagement_id": engagement_id,
        "user_id": payload.user_id,
        "role": payload.role,
        "added": True,
    }


@router.delete(
    "/{engagement_id}/members/{user_id}",
    status_code=status.HTTP_204_NO_CONTENT,
)
def remove_member(
    engagement_id: str,
    user_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    _check_lead_or_admin(db, user, engagement_id)
    member = (
        db.query(EngagementMember)
        .filter(
            EngagementMember.engagement_id == engagement_id,
            EngagementMember.user_id == user_id,
        )
        .first()
    )
    if member is None:
        return
    db.delete(member)
    db.commit()
    record_operator_action(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="engagement_member_remove",
        target=user_id,
        command="DELETE /members",
        result_summary="removed",
    )


@router.post("/{engagement_id}/kill-switch")
def flip_kill_switch(
    engagement_id: str,
    payload: KillSwitchPayload,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    _check_lead_or_admin(db, user, engagement_id)
    eng.kill_switch_active = bool(payload.active)
    db.add(eng)
    db.commit()
    record_operator_action(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="engagement_kill_switch",
        target=eng.client_name,
        command=f"kill-switch={payload.active}",
        result_summary="ON" if payload.active else "OFF",
    )
    return {
        "engagement_id": engagement_id,
        "kill_switch_active": eng.kill_switch_active,
    }


@router.post("/{engagement_id}/close")
def close_engagement(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    _check_lead_or_admin(db, user, engagement_id)
    eng.status = "closed"
    eng.kill_switch_active = True
    db.add(eng)
    db.commit()
    record_operator_action(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="engagement_close",
        target=eng.client_name,
        command="POST /close",
        result_summary="closed",
    )
    return {"engagement_id": engagement_id, "status": "closed"}


@router.get("/{engagement_id}/audit-log")
def list_audit_log(
    engagement_id: str,
    action_type: str | None = None,
    in_scope: bool | None = None,
    since: datetime | None = None,
    until: datetime | None = None,
    page: int = Query(1, ge=1),
    per_page: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    q = db.query(OperatorAuditLog).filter(OperatorAuditLog.engagement_id == engagement_id)
    if action_type:
        q = q.filter(OperatorAuditLog.action_type == action_type)
    if in_scope is not None:
        q = q.filter(OperatorAuditLog.in_scope == in_scope)
    if since:
        q = q.filter(OperatorAuditLog.timestamp >= since)
    if until:
        q = q.filter(OperatorAuditLog.timestamp <= until)
    total = q.count()
    items = (
        q.order_by(desc(OperatorAuditLog.timestamp))
        .offset((page - 1) * per_page)
        .limit(per_page)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "per_page": per_page,
        "items": [
            AuditEntryOut(
                id=l.id,
                engagement_id=l.engagement_id,
                user_id=l.user_id,
                action_type=l.action_type,
                target=l.target,
                command=l.command,
                result_summary=l.result_summary,
                timestamp=l.timestamp,
                signature=l.signature,
                in_scope=l.in_scope,
            ).model_dump()
            for l in items
        ],
    }


@router.get("/{engagement_id}/audit-log/verify")
def verify_audit_log(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    items = db.query(OperatorAuditLog).filter(OperatorAuditLog.engagement_id == engagement_id).all()
    valid = 0
    tampered: list[str] = []
    for l in items:
        if verify_audit_entry(l):
            valid += 1
        else:
            tampered.append(l.id)
    return {
        "engagement_id": engagement_id,
        "total": len(items),
        "valid": valid,
        "tampered_count": len(tampered),
        "tampered_ids": tampered[:50],
    }


@router.post("/{engagement_id}/roe-upload")
async def upload_roe(
    engagement_id: str,
    file: UploadFile = File(...),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    eng = db.get(Engagement, engagement_id)
    if eng is None:
        raise HTTPException(status_code=404, detail="Engagement not found")
    _check_lead_or_admin(db, user, engagement_id)

    settings = get_settings()
    base = settings.SLIVER_BUILD_OUTPUT_DIR or "/data/sliver/builds"
    roe_dir = os.path.join(os.path.dirname(base), "roe")
    try:
        os.makedirs(roe_dir, exist_ok=True)
    except Exception:  # noqa: BLE001
        logger.exception("roe_dir_create_failed")
        raise HTTPException(status_code=500, detail="Cannot create RoE storage")

    safe_name = os.path.basename(file.filename or "roe.pdf")
    dst = os.path.join(roe_dir, f"{engagement_id}_{safe_name}")
    try:
        content = await file.read()
        with open(dst, "wb") as fh:
            fh.write(content)
    except Exception:  # noqa: BLE001
        logger.exception("roe_write_failed")
        raise HTTPException(status_code=500, detail="Cannot persist RoE file")

    eng.roe_document_path = dst
    db.add(eng)
    db.commit()
    record_operator_action(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="engagement_roe_upload",
        target=safe_name,
        command="POST /roe-upload",
        result_summary=f"size={len(content)}",
    )
    return {
        "engagement_id": engagement_id,
        "roe_document_path": dst,
        "size_bytes": len(content),
    }
