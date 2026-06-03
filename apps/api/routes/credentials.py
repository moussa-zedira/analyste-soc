"""Routes /redteam/credentials — extraction + vault (V4.7 Lot A).

Expose secretsdump, kerberoast, AS-REP roast avec garde-fous engagement
(kill-switch/scope/dates) et persistance dans harvested_credentials.
"""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.auth import get_current_user
from apps.api.db.session import get_db
from apps.api.models.credential import HarvestedCredential
from apps.api.models.user import User
from apps.api.pentest.engagement.audit import record_operator_action
from apps.api.pentest.post_exploit import browser_creds, secrets_extract

logger = logging.getLogger("apps.api.pentest.credentials")
router = APIRouter(prefix="/redteam/credentials", tags=["Red Team Credentials"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------


class SecretsdumpIn(BaseModel):
    engagement_id: str | None = None
    target: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    password: str | None = None
    domain: str | None = None
    hashes: str | None = None
    just_dc: bool = False
    just_dc_user: str | None = None


class KerberoastIn(BaseModel):
    engagement_id: str | None = None
    target_dc: str = Field(..., min_length=1)
    username: str = Field(..., min_length=1)
    password: str | None = None
    domain: str = ""
    hashes: str | None = None


class AsrepRoastIn(BaseModel):
    engagement_id: str | None = None
    target_dc: str = Field(..., min_length=1)
    domain: str = Field(..., min_length=1)
    users: list[str] | None = None
    userfile: str | None = None


class BrowserIngestIn(BaseModel):
    engagement_id: str | None = None
    host_target: str = Field(..., min_length=1)
    family: str = Field(..., description="chromium | firefox")
    raw: Any = Field(..., description="Dump decrypte (dict ou list)")


class BrowserPlanIn(BaseModel):
    family: str = Field(..., description="chromium | firefox")
    os_name: str = "windows"


class CredentialOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    engagement_id: str | None
    source: str
    cred_type: str
    target: str
    identifier: str
    fingerprint: str
    mitre_technique: str
    harvested_by: str | None
    harvested_at: datetime
    notes: str


# ---------------------------------------------------------------------------
# Redaction helpers
# ---------------------------------------------------------------------------


def _redact_secret(s: str) -> str:
    """Masque le milieu d'un secret pour affichage (ex: '5e884898...5db2e' )."""
    if not s or len(s) <= 12:
        return "***"
    return f"{s[:6]}...{s[-6:]}"


def _redact_cred_data(entry: HarvestedCredential) -> dict:
    data = dict(entry.data or {})
    for k in ("nt_hash", "lm_hash", "hash", "key"):
        if k in data and isinstance(data[k], str):
            data[k] = _redact_secret(data[k])
    return data


# ---------------------------------------------------------------------------
# Authorization helper
# ---------------------------------------------------------------------------


def _require_operator(user: User) -> None:
    if user.role not in ("admin", "lead"):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="admin or lead role required",
        )


# ---------------------------------------------------------------------------
# Actions
# ---------------------------------------------------------------------------


@router.post("/secretsdump", status_code=status.HTTP_200_OK)
async def run_secretsdump(
    payload: SecretsdumpIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    """Execute impacket-secretsdump + persiste les hashes uniques."""
    _require_operator(user)

    try:
        res = await secrets_extract.secretsdump_and_store(
            db,
            engagement_id=payload.engagement_id,
            target=payload.target,
            username=payload.username,
            password=payload.password,
            domain=payload.domain,
            hashes=payload.hashes,
            just_dc=payload.just_dc,
            just_dc_user=payload.just_dc_user,
            user_id=user.id,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("secretsdump_route_failed")
        raise HTTPException(status_code=500, detail=f"secretsdump: {exc}")

    try:
        record_operator_action(
            db,
            engagement_id=payload.engagement_id,
            user_id=user.id,
            action_type="credential_extract",
            target=payload.target,
            command="impacket-secretsdump",
            result_summary=(
                f"persisted={res['persisted']} skipped={res['skipped_duplicates']} "
                f"status={res['impacket']['status']}"
            ),
        )
    except Exception:
        logger.exception("secretsdump_audit_failed")
    return res


@router.post("/kerberoast", status_code=status.HTTP_200_OK)
async def run_kerberoast(
    payload: KerberoastIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _require_operator(user)
    try:
        res = await secrets_extract.kerberoast_and_store(
            db,
            engagement_id=payload.engagement_id,
            target_dc=payload.target_dc,
            username=payload.username,
            password=payload.password,
            domain=payload.domain,
            hashes=payload.hashes,
            user_id=user.id,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("kerberoast_route_failed")
        raise HTTPException(status_code=500, detail=f"kerberoast: {exc}")

    try:
        record_operator_action(
            db,
            engagement_id=payload.engagement_id,
            user_id=user.id,
            action_type="credential_extract",
            target=payload.target_dc,
            command="impacket-GetUserSPNs",
            result_summary=f"persisted={res['persisted']}",
        )
    except Exception:
        logger.exception("kerberoast_audit_failed")
    return res


@router.post("/asrep-roast", status_code=status.HTTP_200_OK)
async def run_asrep_roast(
    payload: AsrepRoastIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _require_operator(user)
    try:
        res = await secrets_extract.asrep_roast_and_store(
            db,
            engagement_id=payload.engagement_id,
            target_dc=payload.target_dc,
            domain=payload.domain,
            users=payload.users,
            userfile=payload.userfile,
            user_id=user.id,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("asrep_roast_route_failed")
        raise HTTPException(status_code=500, detail=f"asrep-roast: {exc}")

    try:
        record_operator_action(
            db,
            engagement_id=payload.engagement_id,
            user_id=user.id,
            action_type="credential_extract",
            target=payload.target_dc,
            command="impacket-GetNPUsers",
            result_summary=f"persisted={res['persisted']}",
        )
    except Exception:
        logger.exception("asrep_audit_failed")
    return res


# ---------------------------------------------------------------------------
# Browser credentials (T1555.003)
# ---------------------------------------------------------------------------


@router.post("/browser/plan", status_code=status.HTTP_200_OK)
def browser_plan(
    payload: BrowserPlanIn,
    user: User = Depends(get_current_user),
) -> dict:
    """Renvoie les commandes a executer sur l'host compromis."""
    _require_operator(user)
    fam = (payload.family or "").lower()
    if fam in ("chromium", "chrome", "edge", "brave"):
        return browser_creds.plan_chromium(os_name=payload.os_name)
    if fam == "firefox":
        return browser_creds.plan_firefox()
    raise HTTPException(status_code=400, detail="family must be chromium|firefox")


@router.post("/browser/ingest", status_code=status.HTTP_200_OK)
async def browser_ingest(
    payload: BrowserIngestIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    """Persiste les credentials decryptes recus du host compromis."""
    _require_operator(user)
    try:
        res = await browser_creds.ingest_browser_creds(
            db,
            engagement_id=payload.engagement_id,
            host_target=payload.host_target,
            family=payload.family,
            raw=payload.raw,
            user_id=user.id,
        )
    except HTTPException:
        raise
    except Exception as exc:  # noqa: BLE001
        logger.exception("browser_ingest_failed")
        raise HTTPException(status_code=500, detail=f"browser ingest: {exc}")

    try:
        record_operator_action(
            db,
            engagement_id=payload.engagement_id,
            user_id=user.id,
            action_type="credential_browser_ingest",
            target=payload.host_target,
            command=f"family={payload.family}",
            result_summary=(
                f"persisted={res.get('persisted', 0)} skipped={res.get('skipped_duplicates', 0)}"
            ),
        )
    except Exception:
        logger.exception("browser_ingest_audit_failed")
    return res


# ---------------------------------------------------------------------------
# Vault browse
# ---------------------------------------------------------------------------


@router.get("", response_model=list[CredentialOut])
def list_credentials(
    engagement_id: str | None = Query(None),
    cred_type: str | None = Query(None),
    source: str | None = Query(None),
    limit: int = Query(200, ge=1, le=1000),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[CredentialOut]:
    q = db.query(HarvestedCredential)
    if engagement_id:
        q = q.filter(HarvestedCredential.engagement_id == engagement_id)
    if cred_type:
        q = q.filter(HarvestedCredential.cred_type == cred_type)
    if source:
        q = q.filter(HarvestedCredential.source == source)
    items = q.order_by(desc(HarvestedCredential.harvested_at)).offset(offset).limit(limit).all()
    return [CredentialOut.model_validate(c) for c in items]


@router.get("/{cred_id}")
def get_credential(
    cred_id: str,
    reveal: bool = Query(False, description="Admin only: inclut le secret brut"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    entry = db.get(HarvestedCredential, cred_id)
    if not entry:
        raise HTTPException(status_code=404, detail="credential not found")

    if reveal:
        if user.role != "admin":
            raise HTTPException(status_code=403, detail="admin role required to reveal secret")
        data = entry.data or {}
        try:
            record_operator_action(
                db,
                engagement_id=entry.engagement_id,
                user_id=user.id,
                action_type="credential_reveal",
                target=entry.target,
                command="",
                result_summary=(f"cred_id={cred_id} type={entry.cred_type}"),
            )
        except Exception:
            logger.exception("reveal_audit_failed")
    else:
        data = _redact_cred_data(entry)

    base = CredentialOut.model_validate(entry).model_dump(mode="json")
    base["data"] = data
    return base


@router.delete("/{cred_id}", status_code=204)
def delete_credential(
    cred_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    if user.role != "admin":
        raise HTTPException(status_code=403, detail="admin role required")
    entry = db.get(HarvestedCredential, cred_id)
    if not entry:
        raise HTTPException(status_code=404, detail="credential not found")
    eng_id = entry.engagement_id
    tgt = entry.target
    ctype = entry.cred_type
    db.delete(entry)
    try:
        db.commit()
    except Exception:
        db.rollback()
        raise HTTPException(status_code=500, detail="delete failed")
    try:
        record_operator_action(
            db,
            engagement_id=eng_id,
            user_id=user.id,
            action_type="credential_delete",
            target=tgt,
            command="",
            result_summary=f"cred_id={cred_id} type={ctype}",
        )
    except Exception:
        logger.exception("delete_audit_failed")
    return None


@router.get("/stats/summary")
def credentials_stats(
    engagement_id: str | None = Query(None),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    q = db.query(HarvestedCredential)
    if engagement_id:
        q = q.filter(HarvestedCredential.engagement_id == engagement_id)
    rows = q.all()
    by_type: dict[str, int] = {}
    by_source: dict[str, int] = {}
    mitre: dict[str, int] = {}
    for r in rows:
        by_type[r.cred_type] = by_type.get(r.cred_type, 0) + 1
        by_source[r.source] = by_source.get(r.source, 0) + 1
        if r.mitre_technique:
            mitre[r.mitre_technique] = mitre.get(r.mitre_technique, 0) + 1
    return {
        "total": len(rows),
        "by_type": by_type,
        "by_source": by_source,
        "by_mitre_technique": mitre,
    }
