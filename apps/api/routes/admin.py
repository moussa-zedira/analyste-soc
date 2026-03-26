"""Panel d'administration — gestion des utilisateurs et journal d'audit."""

from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel
from sqlalchemy.orm import Session

from apps.api.auth import RoleChecker, get_current_user
from apps.api.db.session import get_db
from apps.api.models.audit_log import AuditLog
from apps.api.models.user import User
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class UserOut(BaseModel):
    """Représentation publique d'un utilisateur."""

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: str


class UserUpdate(BaseModel):
    """Champs modifiables d'un utilisateur."""

    role: str | None = None
    is_active: bool | None = None


class AuditLogOut(BaseModel):
    """Entrée du journal d'audit."""

    id: str
    user_id: str | None
    username: str | None
    action: str
    target: str | None
    details: str
    ip_address: str | None
    created_at: str


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _log_action(
    db: Session,
    *,
    user_id: str | None = None,
    username: str | None = None,
    action: str,
    target: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Enregistre une action dans le journal d'audit."""
    entry = AuditLog(
        id=str(uuid.uuid4()),
        user_id=user_id,
        username=username,
        action=action,
        target=target,
        details=json.dumps(details or {}),
        ip_address=ip_address,
        created_at=datetime.now(timezone.utc),
    )
    db.add(entry)
    db.commit()


# ---------------------------------------------------------------------------
# Endpoints — Utilisateurs
# ---------------------------------------------------------------------------


@router.get("/users", response_model=list[UserOut])
def list_users(
    db: Session = Depends(get_db),
    _admin: User = Depends(RoleChecker("admin")),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> list[UserOut]:
    """Liste tous les utilisateurs (admin uniquement)."""
    users = (
        db.query(User)
        .order_by(User.created_at.desc())
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [
        UserOut(
            id=u.id,
            username=u.username,
            email=u.email,
            role=u.role,
            is_active=u.is_active,
            created_at=u.created_at.isoformat() if u.created_at else "",
        )
        for u in users
    ]


@router.patch("/users/{user_id}", response_model=UserOut)
def update_user(
    user_id: str,
    body: UserUpdate,
    db: Session = Depends(get_db),
    admin: User = Depends(RoleChecker("admin")),
) -> UserOut:
    """Modifie le rôle ou le statut actif d'un utilisateur (admin uniquement)."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")

    changes: dict = {}
    if body.role is not None and body.role in ("analyst", "lead", "admin"):
        changes["role"] = f"{user.role} -> {body.role}"
        user.role = body.role
    if body.is_active is not None:
        changes["is_active"] = f"{user.is_active} -> {body.is_active}"
        user.is_active = body.is_active

    db.commit()
    db.refresh(user)

    _log_action(
        db,
        user_id=admin.id,
        username=admin.username,
        action="update_user",
        target=user.username,
        details=changes,
    )

    return UserOut(
        id=user.id,
        username=user.username,
        email=user.email,
        role=user.role,
        is_active=user.is_active,
        created_at=user.created_at.isoformat() if user.created_at else "",
    )


@router.delete("/users/{user_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_user(
    user_id: str,
    db: Session = Depends(get_db),
    admin: User = Depends(RoleChecker("admin")),
) -> None:
    """Supprime un utilisateur (admin uniquement)."""
    user = db.get(User, user_id)
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Utilisateur non trouvé")
    if user.id == admin.id:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Impossible de supprimer votre propre compte")

    username = user.username
    db.delete(user)
    db.commit()

    _log_action(
        db,
        user_id=admin.id,
        username=admin.username,
        action="delete_user",
        target=username,
    )


# ---------------------------------------------------------------------------
# Endpoints — Journal d'audit
# ---------------------------------------------------------------------------


@router.get("/audit-log", response_model=list[AuditLogOut])
def list_audit_log(
    db: Session = Depends(get_db),
    _admin: User = Depends(RoleChecker("admin")),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    action: str | None = None,
) -> list[AuditLogOut]:
    """Retourne le journal d'audit (admin uniquement)."""
    query = db.query(AuditLog).order_by(AuditLog.created_at.desc())
    if action:
        query = query.filter(AuditLog.action == action)
    entries = query.offset(offset).limit(limit).all()
    return [
        AuditLogOut(
            id=e.id,
            user_id=e.user_id,
            username=e.username,
            action=e.action,
            target=e.target,
            details=e.details,
            ip_address=e.ip_address,
            created_at=e.created_at.isoformat() if e.created_at else "",
        )
        for e in entries
    ]
