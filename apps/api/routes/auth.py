"""API Authentification — inscription, connexion et informations utilisateur."""

from __future__ import annotations

import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request, status
from pydantic import BaseModel, EmailStr, ConfigDict
from sqlalchemy.orm import Session

from apps.api.auth import (
    create_access_token,
    get_current_user,
    hash_password,
    verify_password,
)
from apps.api.db.session import get_db
from apps.api.middleware.rate_limit import limiter
from apps.api.models.user import User

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
    """Reponse contenant le jeton d'acces."""

    access_token: str
    token_type: str = "bearer"


class UserRead(BaseModel):
    """Schema de lecture d'un utilisateur."""

    model_config = ConfigDict(from_attributes=True)

    id: str
    username: str
    email: str
    role: str
    is_active: bool
    created_at: datetime


@router.post("/register", response_model=UserRead, status_code=status.HTTP_201_CREATED)
@limiter.limit("10/hour")
def register(request: Request, payload: RegisterRequest, db: Session = Depends(get_db)) -> User:
    """Inscrire un nouveau compte utilisateur."""
    existing = db.query(User).filter(
        (User.username == payload.username) | (User.email == payload.email)
    ).first()
    if existing:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="Username or email already exists",
        )

    if payload.role not in ("analyst", "lead", "admin"):
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
    return user


@router.post("/login", response_model=TokenResponse)
@limiter.limit("5/minute")
def login(request: Request, payload: LoginRequest, db: Session = Depends(get_db)) -> dict:
    """Authentifier et retourner un jeton JWT."""
    user = db.query(User).filter(User.username == payload.username).first()
    if user is None or not verify_password(payload.password, user.hashed_password):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid credentials",
        )
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Account is deactivated",
        )

    token = create_access_token({"sub": user.id, "role": user.role})
    return {"access_token": token, "token_type": "bearer"}


@router.get("/me", response_model=UserRead)
def me(user: User = Depends(get_current_user)) -> User:
    """Retourner l'utilisateur actuellement authentifie."""
    return user
