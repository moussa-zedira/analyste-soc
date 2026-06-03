"""API Authentification — inscription, connexion, refresh et logout."""

from __future__ import annotations

import hashlib
import io
import json
import logging
import secrets as stdsecrets
import uuid
from base64 import b64encode
from datetime import UTC, datetime

import pyotp
import qrcode
from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy import func
from sqlalchemy.orm import Session

from apps.api.auth import (
    _decode_and_validate,
    create_access_token,
    create_refresh_token,
    decode_token,
    get_current_user,
    hash_password,
    revoke_jti,
    verify_password,
)
from apps.api.db.session import get_db
from apps.api.middleware.rate_limit import limiter
from apps.api.models.audit_log import AuditLog
from apps.api.models.scan_history import ScanHistory
from apps.api.models.user import User
from apps.api.models.user_api_key import UserApiKey
from apps.api.models.user_preferences import UserPreferences
from apps.api.observability import record_login

logger = logging.getLogger(__name__)

router = APIRouter()


def _write_audit(
    db: Session,
    *,
    user_id: str | None,
    username: str | None,
    action: str,
    target: str | None = None,
    details: dict | None = None,
    ip_address: str | None = None,
) -> None:
    """Enregistre une entrée dans le journal d'audit (best-effort)."""
    try:
        db.add(
            AuditLog(
                id=str(uuid.uuid4()),
                user_id=user_id,
                username=username,
                action=action,
                target=target,
                details=json.dumps(details or {}),
                ip_address=ip_address,
                created_at=datetime.now(UTC),
            )
        )
        db.commit()
    except Exception:
        logger.debug("audit log write failed", exc_info=True)
        db.rollback()


def _client_ip(request: Request) -> str | None:
    xff = request.headers.get("x-forwarded-for")
    if xff:
        return xff.split(",")[0].strip()
    return request.client.host if request.client else None


class RegisterRequest(BaseModel):
    """Donnees de la requete d'inscription."""

    username: str
    email: str
    password: str
    role: str = "analyst"


class LoginRequest(BaseModel):
    """Donnees de la requete de connexion."""

    username: str
    password: str
    totp_code: str | None = None


class TokenResponse(BaseModel):
    """Reponse contenant access + refresh tokens."""

    access_token: str
    refresh_token: str
    token_type: str = "bearer"


class RefreshRequest(BaseModel):
    """Corps de la requete /auth/refresh."""

    refresh_token: str


class UserRead(BaseModel):
    """Schema de lecture d'un utilisateur."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


def _issue_token_pair(user: User) -> dict:
    claims = {"sub": user.id, "role": user.role}
    return {
        "access_token": create_access_token(claims),
        "refresh_token": create_refresh_token(claims),
        "token_type": "bearer",
    }


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)) -> User:
    """Inscrire un nouveau compte utilisateur."""
    existing = (
        db.query(User)
        .filter((User.username == payload.username) | (User.email == payload.email))
        .first()
    )
    if existing:
        record_login("register", success=False)
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )

    if payload.role not in ("analyst", "lead", "admin"):
        record_login("register", success=False)
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Role must be analyst, lead, or admin",
        )

    user = User(
        id=str(uuid.uuid4()),
        username=payload.username,
        email=payload.email,
        hashed_password=hash_password(payload.password),
        role=payload.role,
        is_active=True,
        created_at=datetime.now(UTC),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_login("register", success=True)
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="register",
        ip_address=_client_ip(request),
    )
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)) -> dict:
    """Authentifier et retourner une paire access + refresh."""
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.hashed_password):
        record_login("login", success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        record_login("login", success=False)
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )
    if user.totp_enabled and user.totp_secret:
        if not payload.totp_code:
            record_login("login", success=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="2FA code required",
            )
        if not pyotp.TOTP(user.totp_secret).verify(payload.totp_code, valid_window=1):
            record_login("login", success=False)
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Invalid 2FA code",
            )
    record_login("login", success=True)
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="login",
        ip_address=_client_ip(request),
    )
    return _issue_token_pair(user)


@router.post("/refresh", response_model=TokenResponse)
@limiter.limit("30/minute")
def refresh(request: Request, payload: RefreshRequest, db: Session = Depends(get_db)) -> dict:
    """Echange un refresh token valide contre une nouvelle paire de jetons.

    L'ancien refresh est revoque (rotation) — un refresh ne sert qu'une fois.
    """
    refresh_payload = _decode_and_validate(payload.refresh_token, "refresh")
    user_id: str = refresh_payload.get("sub", "")
    user = db.get(User, user_id)
    if user is None or not user.is_active:
        record_login("refresh", success=False)
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found or inactive",
        )
    revoke_jti(refresh_payload.get("jti", ""), refresh_payload.get("exp", 0))
    record_login("refresh", success=True)
    return _issue_token_pair(user)


@router.post("/logout", status_code=status.HTTP_204_NO_CONTENT)
def logout(
    request: Request,
    payload: RefreshRequest | None = None,
    db: Session = Depends(get_db),
) -> None:
    """Revoque l'access courant et, si fourni, le refresh associe."""
    auth_header = request.headers.get("Authorization", "")
    user_id: str | None = None
    if auth_header.startswith("Bearer "):
        try:
            access_payload = decode_token(auth_header[7:])
            user_id = access_payload.get("sub")
            revoke_jti(access_payload.get("jti", ""), access_payload.get("exp", 0))
        except Exception:
            logger.debug("auth: ignored exception", exc_info=True)

    if payload and payload.refresh_token:
        try:
            ref = decode_token(payload.refresh_token)
            revoke_jti(ref.get("jti", ""), ref.get("exp", 0))
        except Exception:
            logger.debug("auth: ignored exception", exc_info=True)
    record_login("logout", success=True)
    if user_id:
        username = None
        try:
            u = db.get(User, user_id)
            username = u.username if u else None
        except Exception:
            logger.debug("auth: ignored exception", exc_info=True)
        _write_audit(
            db,
            user_id=user_id,
            username=username,
            action="logout",
            ip_address=_client_ip(request),
        )


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)) -> User:
    """Retourner l'utilisateur actuellement authentifie."""
    return user


class PasswordChangeRequest(BaseModel):
    current_password: str
    new_password: str


@router.post("/me/password", status_code=status.HTTP_204_NO_CONTENT)
def change_password(
    payload: PasswordChangeRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    """Change le mot de passe de l'utilisateur courant."""
    if not verify_password(payload.current_password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid current password",
        )
    if len(payload.new_password) < 8:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="New password must be at least 8 characters",
        )
    user.hashed_password = hash_password(payload.new_password)
    db.commit()
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="password_change",
        ip_address=_client_ip(request),
    )


class UserStats(BaseModel):
    """Statistiques d'activite de l'utilisateur courant."""

    total_logins: int
    events_reviewed: int
    incidents_handled: int
    scans_performed: int
    last_login: datetime | None = None


class ActivityEntry(BaseModel):
    """Entree du journal d'activite utilisateur."""

    id: str
    action: str
    target: str | None = None
    ip_address: str | None = None
    created_at: datetime


class ActivityResponse(BaseModel):
    total: int
    items: list[ActivityEntry]


@router.get("/me/stats", response_model=UserStats)
def me_stats(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserStats:
    """Statistiques d'activite agregees pour l'utilisateur courant.

    Calculees depuis audit_logs (login/events/incidents) et scan_history.
    """
    total_logins = (
        db.query(func.count(AuditLog.id))
        .filter(AuditLog.user_id == user.id, AuditLog.action == "login")
        .scalar()
        or 0
    )
    events_reviewed = (
        db.query(func.count(AuditLog.id))
        .filter(AuditLog.user_id == user.id, AuditLog.action == "event_review")
        .scalar()
        or 0
    )
    incidents_handled = (
        db.query(func.count(AuditLog.id))
        .filter(
            AuditLog.user_id == user.id,
            AuditLog.action.in_(
                ["incident_ack", "incident_close", "incident_update", "incident_assign"]
            ),
        )
        .scalar()
        or 0
    )
    scans_performed = (
        db.query(func.count(ScanHistory.id)).filter(ScanHistory.scanned_by == user.id).scalar() or 0
    )
    last_login = (
        db.query(AuditLog.created_at)
        .filter(AuditLog.user_id == user.id, AuditLog.action == "login")
        .order_by(AuditLog.created_at.desc())
        .limit(1)
        .scalar()
    )
    return UserStats(
        total_logins=int(total_logins),
        events_reviewed=int(events_reviewed),
        incidents_handled=int(incidents_handled),
        scans_performed=int(scans_performed),
        last_login=last_login,
    )


@router.get("/me/activity", response_model=ActivityResponse)
def me_activity(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(20, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ActivityResponse:
    """Journal d'activite de l'utilisateur courant (derniers audit_logs)."""
    base = db.query(AuditLog).filter(AuditLog.user_id == user.id)
    total = base.count()
    rows = base.order_by(AuditLog.created_at.desc()).offset(offset).limit(limit).all()
    items = [
        ActivityEntry(
            id=r.id,
            action=r.action,
            target=r.target,
            ip_address=r.ip_address,
            created_at=r.created_at,
        )
        for r in rows
    ]
    return ActivityResponse(total=total, items=items)


# ---------------------------------------------------------------------------
# Preferences
# ---------------------------------------------------------------------------


class PreferencesModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    notif_email: bool = True
    notif_browser: bool = True
    notif_critical_only: bool = False
    default_layout: str = "grid"
    timezone: str = "UTC"


def _get_or_create_preferences(db: Session, user_id: str) -> UserPreferences:
    prefs = db.get(UserPreferences, user_id)
    if prefs is None:
        prefs = UserPreferences(
            user_id=user_id,
            notif_email=True,
            notif_browser=True,
            notif_critical_only=False,
            default_layout="grid",
            timezone="UTC",
            updated_at=datetime.now(UTC),
        )
        db.add(prefs)
        db.commit()
        db.refresh(prefs)
    return prefs


@router.get("/me/preferences", response_model=PreferencesModel)
def get_preferences(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserPreferences:
    """Preferences UI de l'utilisateur courant."""
    return _get_or_create_preferences(db, user.id)


@router.put("/me/preferences", response_model=PreferencesModel)
def update_preferences(
    payload: PreferencesModel,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> UserPreferences:
    """Met a jour les preferences UI de l'utilisateur courant."""
    if payload.default_layout not in ("grid", "list"):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="default_layout must be grid or list",
        )
    prefs = _get_or_create_preferences(db, user.id)
    prefs.notif_email = payload.notif_email
    prefs.notif_browser = payload.notif_browser
    prefs.notif_critical_only = payload.notif_critical_only
    prefs.default_layout = payload.default_layout
    prefs.timezone = payload.timezone
    prefs.updated_at = datetime.now(UTC)
    db.commit()
    db.refresh(prefs)
    return prefs


# ---------------------------------------------------------------------------
# API Keys per user
# ---------------------------------------------------------------------------


class ApiKeyCreate(BaseModel):
    name: str
    scopes: str = "read"
    expires_in_days: int | None = None


class ApiKeyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    prefix: str
    scopes: str
    last_used_at: datetime | None = None
    created_at: datetime
    expires_at: datetime | None = None
    revoked: bool = False


class ApiKeyCreated(ApiKeyOut):
    """Retourné une seule fois à la création, avec la clé en clair."""

    key: str


def _hash_api_key(raw: str) -> str:
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


@router.get("/me/api-keys", response_model=list[ApiKeyOut])
def list_api_keys(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[UserApiKey]:
    return (
        db.query(UserApiKey)
        .filter(UserApiKey.user_id == user.id)
        .order_by(UserApiKey.created_at.desc())
        .all()
    )


@router.post("/me/api-keys", response_model=ApiKeyCreated, status_code=status.HTTP_201_CREATED)
def create_api_key(
    payload: ApiKeyCreate,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ApiKeyCreated:
    if not payload.name.strip():
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="name is required")
    raw = f"cd_{stdsecrets.token_urlsafe(32)}"
    prefix = raw[:10]
    now = datetime.now(UTC)
    expires_at: datetime | None = None
    if payload.expires_in_days and payload.expires_in_days > 0:
        from datetime import timedelta

        expires_at = now + timedelta(days=payload.expires_in_days)
    entry = UserApiKey(
        id=str(uuid.uuid4()),
        user_id=user.id,
        name=payload.name.strip(),
        prefix=prefix,
        hashed_key=_hash_api_key(raw),
        scopes=payload.scopes or "read",
        created_at=now,
        expires_at=expires_at,
        revoked=False,
    )
    db.add(entry)
    db.commit()
    db.refresh(entry)
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="api_key_create",
        target=entry.id,
        details={"name": entry.name, "scopes": entry.scopes},
        ip_address=_client_ip(request),
    )
    return ApiKeyCreated(
        id=entry.id,
        name=entry.name,
        prefix=entry.prefix,
        scopes=entry.scopes,
        last_used_at=entry.last_used_at,
        created_at=entry.created_at,
        expires_at=entry.expires_at,
        revoked=entry.revoked,
        key=raw,
    )


@router.delete("/me/api-keys/{key_id}", status_code=status.HTTP_204_NO_CONTENT)
def revoke_api_key(
    key_id: str,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> None:
    entry = db.get(UserApiKey, key_id)
    if entry is None or entry.user_id != user.id:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="API key not found")
    entry.revoked = True
    db.commit()
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="api_key_revoke",
        target=key_id,
        ip_address=_client_ip(request),
    )


# ---------------------------------------------------------------------------
# 2FA TOTP
# ---------------------------------------------------------------------------


class TotpSetupResponse(BaseModel):
    secret: str
    otpauth_url: str
    qr_png_base64: str


class TotpEnableRequest(BaseModel):
    code: str


class TotpDisableRequest(BaseModel):
    password: str


class TotpStatus(BaseModel):
    enabled: bool


@router.get("/me/2fa/status", response_model=TotpStatus)
def totp_status(user: User = Depends(get_current_user)) -> TotpStatus:
    return TotpStatus(enabled=bool(user.totp_enabled))


@router.post("/me/2fa/setup", response_model=TotpSetupResponse)
def totp_setup(
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TotpSetupResponse:
    """Genere un secret TOTP et retourne le QR (non encore active).

    Le secret est stocke mais totp_enabled reste false jusqu'au verify.
    """
    secret = pyotp.random_base32()
    user.totp_secret = secret
    user.totp_enabled = False
    db.commit()
    otpauth = pyotp.totp.TOTP(secret).provisioning_uri(name=user.username, issuer_name="CyberDef")
    img = qrcode.make(otpauth)
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    qr_b64 = b64encode(buf.getvalue()).decode("ascii")
    return TotpSetupResponse(secret=secret, otpauth_url=otpauth, qr_png_base64=qr_b64)


@router.post("/me/2fa/enable", response_model=TotpStatus)
def totp_enable(
    payload: TotpEnableRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TotpStatus:
    if not user.totp_secret:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="2FA setup not started",
        )
    if not pyotp.TOTP(user.totp_secret).verify(payload.code, valid_window=1):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid 2FA code")
    user.totp_enabled = True
    db.commit()
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="2fa_enable",
        ip_address=_client_ip(request),
    )
    return TotpStatus(enabled=True)


@router.post("/me/2fa/disable", response_model=TotpStatus)
def totp_disable(
    payload: TotpDisableRequest,
    request: Request,
    user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> TotpStatus:
    if not verify_password(payload.password, user.hashed_password):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid password")
    user.totp_secret = None
    user.totp_enabled = False
    db.commit()
    _write_audit(
        db,
        user_id=user.id,
        username=user.username,
        action="2fa_disable",
        ip_address=_client_ip(request),
    )
    return TotpStatus(enabled=False)
