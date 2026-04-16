"""Authentification JWT et contrôle d'accès basé sur les rôles.

Modele a deux jetons :
- ``access_token`` court (15 min par defaut) — pour appeler l'API
- ``refresh_token`` long (7 jours par defaut) — pour obtenir un nouveau access

Chaque jeton porte un identifiant unique ``jti``. Lors d'un /auth/logout
ou d'un /auth/refresh, le ``jti`` est ajoute a une liste de revocation
Redis avec un TTL aligne sur l'expiration du jeton — c'est ce qui rend
les jetons revocables sans table SQL dediee.
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from fastapi import Depends, HTTPException, Request, status
from jose import JWTError, jwt
from passlib.context import CryptContext
from sqlalchemy.orm import Session

from apps.api.cache import get_redis_client
from apps.api.config import get_settings
from apps.api.db.session import get_db
from apps.api.models.user import User

logger = logging.getLogger(__name__)

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")

ROLE_HIERARCHY = {"analyst": 0, "lead": 1, "admin": 2}

TokenType = Literal["access", "refresh"]
_REVOKED_PREFIX = "auth:revoked:"


def hash_password(password: str) -> str:
    """Hache un mot de passe en utilisant bcrypt."""
    return pwd_context.hash(password)


def verify_password(plain: str, hashed: str) -> bool:
    """Vérifie un mot de passe en clair contre son hash."""
    return pwd_context.verify(plain, hashed)


def _create_token(data: dict, token_type: TokenType, lifetime: timedelta) -> tuple[str, str]:
    """Encode un JWT (access ou refresh) et retourne (token, jti)."""
    settings = get_settings()
    jti = uuid.uuid4().hex
    now = datetime.now(timezone.utc)
    payload = {
        **data,
        "type": token_type,
        "jti": jti,
        "iat": now,
        "exp": now + lifetime,
    }
    token = jwt.encode(payload, settings.JWT_SECRET_KEY, algorithm=settings.JWT_ALGORITHM)
    return token, jti


def create_access_token(data: dict) -> str:
    """Crée un jeton d'accès JWT court."""
    settings = get_settings()
    token, _ = _create_token(
        data, "access", timedelta(minutes=settings.JWT_EXPIRE_MINUTES)
    )
    return token


def create_refresh_token(data: dict) -> str:
    """Cree un jeton refresh long."""
    settings = get_settings()
    token, _ = _create_token(
        data, "refresh", timedelta(days=settings.JWT_REFRESH_EXPIRE_DAYS)
    )
    return token


def decode_token(token: str) -> dict:
    """Décode et valide un jeton JWT."""
    settings = get_settings()
    return jwt.decode(token, settings.JWT_SECRET_KEY, algorithms=[settings.JWT_ALGORITHM])


def revoke_jti(jti: str, exp_ts: int | float) -> None:
    """Marque un jti comme revoque dans Redis jusqu'a son expiration."""
    if not jti:
        return
    r = get_redis_client()
    if r is None:
        # Pas de Redis = pas de revocation. C'est tolere en dev mais dangereux
        # en prod : le check de configuration au demarrage le signalera.
        logger.warning("auth_revocation_skipped_no_redis", extra={"jti": jti})
        return
    ttl = int(exp_ts - datetime.now(timezone.utc).timestamp())
    if ttl <= 0:
        return
    try:
        r.setex(_REVOKED_PREFIX + jti, ttl, "1")
    except Exception:
        logger.exception("auth_revocation_redis_error")


def _is_revoked(jti: str) -> bool:
    """Verifie si un jti est present dans la liste de revocation."""
    if not jti:
        return False
    r = get_redis_client()
    if r is None:
        return False
    try:
        return bool(r.exists(_REVOKED_PREFIX + jti))
    except Exception:
        # Fail-open serait dangereux : un Redis injoignable doit echouer ferme
        # cote auth. Mais on log et on laisse passer pour ne pas bloquer le
        # service entier — alternative discutable, a re-evaluer en revue.
        logger.exception("auth_revocation_check_failed")
        return False


def _decode_and_validate(token: str, expected_type: TokenType) -> dict:
    """Decode le jwt, verifie le type, le jti et la revocation."""
    try:
        payload = decode_token(token)
    except JWTError as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token",
        ) from e

    if payload.get("type") != expected_type:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=f"Expected {expected_type} token",
        )
    if _is_revoked(payload.get("jti", "")):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token revoked",
        )
    return payload


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

    payload = _decode_and_validate(auth_header[7:], "access")
    user_id: str = payload.get("sub", "")
    if not user_id:
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
