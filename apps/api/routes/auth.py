"""API Authentification — inscription, connexion, refresh et logout."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, ConfigDict
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
from apps.api.models.user import User
from apps.api.observability import record_login

router = APIRouter()


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
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
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
        created_at=datetime.now(timezone.utc),
    )
    db.add(user)
    db.commit()
    db.refresh(user)
    record_login("register", success=True)
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
    record_login("login", success=True)
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
def logout(request: Request, payload: RefreshRequest | None = None) -> None:
    """Revoque l'access courant et, si fourni, le refresh associe."""
    auth_header = request.headers.get("Authorization", "")
    if auth_header.startswith("Bearer "):
        try:
            access_payload = decode_token(auth_header[7:])
            revoke_jti(access_payload.get("jti", ""), access_payload.get("exp", 0))
        except Exception:
            pass

    if payload and payload.refresh_token:
        try:
            ref = decode_token(payload.refresh_token)
            revoke_jti(ref.get("jti", ""), ref.get("exp", 0))
        except Exception:
            pass
    record_login("logout", success=True)


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)) -> User:
    """Retourner l'utilisateur actuellement authentifie."""
    return user
