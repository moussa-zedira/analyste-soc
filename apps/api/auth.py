"""Authentification JWT et contrôle d'accès basé sur les rôles."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.models.user import User

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_HIERARCHY = {"analyst": 0, "lead": 1, "admin": 2}


def hash_password(password: str) -> str:
    """Hache un mot de passe en utilisant bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Vérifie un mot de passe en clair contre son hash."""
    return pwd_context.verify(plain, hashed)


def create_access_token(data: dict) -> str:
    """Crée un jeton d'accès JWT avec une date d'expiration."""
    settings = get_settings()
    to_encode = data.copy()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)


def decode_token(token: str) -> dict:
    """Décode et valide un jeton JWT."""
    settings = get_settings()
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def get_current_user(request: Request, db: Session = Depends(get_db)) -> User:
    """Extrait et valide le jeton JWT depuis l'en-tête Authorization.

    Retourne l'objet User authentifié.
    """
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Missing or invalid Authorization header",
        )

    token = auth_header[7:]
    try:
        payload = decode_token(token)
        user_id: str = payload.get("sub", "")
        if not user_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")
    except JWTError:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Invalid token")

    user = db.get(User, user_id)
    if user is None or not user.is_active:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="User not found or inactive")
    return user


class RoleChecker:
    """Dépendance qui vérifie que le rôle de l'utilisateur atteint un niveau minimum.

    Utilisation : Depends(RoleChecker("lead"))
    """

    def __init__(self, min_role: str) -> None:
        """Initialise le vérificateur avec le rôle minimum requis."""
        self.min_role = min_role

    def __call__(self, user: User = Depends(get_current_user)) -> User:
        """Vérifie le rôle de l'utilisateur et lève 403 si insuffisant."""
        user_level = ROLE_HIERARCHY.get(user.role, 0)
        required_level = ROLE_HIERARCHY.get(self.min_role, 0)
        if user_level < required_level:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Role '{self.min_role}' or higher required",
            )
        return user
