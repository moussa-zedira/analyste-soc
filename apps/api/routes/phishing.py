"""Routes /redteam/phishing (V4.6) — workflow GoPhish enrichi.

Couche workflow/reporting au-dessus de GoPhish (outil tiers public).
Pas de payload custom : on cree un group + une campagne dans GoPhish,
on persiste la campagne en DB, on synchronise les results en boucle,
et on signe l'action dans OperatorAuditLog (V4.3b) avec MITRE T1566.001.

Toutes les routes exigent une session authentifiee (JWT).
"""

from __future__ import annotations

import logging
import uuid
from datetime import datetime, timezone
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import desc
from sqlalchemy.orm import Session

from apps.api.auth import get_current_user
from apps.api.db.session import get_db
from apps.api.models.engagement import Engagement
from apps.api.models.phishing import (
    PhishingCampaign,
    PhishingResult,
    PhishingTarget,
)
from apps.api.models.user import User
from apps.api.pentest.engagement.audit import record_operator_action
from apps.api.pentest.phishing.gophish_client import (
    GoPhishClient,
    GoPhishError,
    GoPhishNotConfigured,
)
from apps.api.pentest.phishing.sync import sync_campaign


logger = logging.getLogger("apps.api.pentest.phishing")
router = APIRouter(prefix="/redteam/phishing", tags=["Red Team Phishing"])


VALID_EVENT_TYPES = {
    "email_sent",
    "email_opened",
    "clicked_link",
    "submitted_data",
    "email_failed",
}


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class TargetIn(BaseModel):
    email: str
    first_name: str = ""
    last_name: str = ""
    position: str = ""


class CreateCampaignIn(BaseModel):
    name: str = Field(..., min_length=1)
    engagement_id: Optional[str] = None
    template_name: str = Field(..., min_length=1)
    landing_page: str = Field(
        default="", description="GoPhish landing page name"
    )
    landing_url: str = Field(..., min_length=1)
    smtp_profile: str = Field(..., min_length=1)
    group_name: str = Field(
        default="",
        description=(
            "Si fourni: reuse un group GoPhish existant. Sinon un group est "
            "cree depuis 'targets'."
        ),
    )
    targets: list[TargetIn] = Field(default_factory=list)
    launch_date: Optional[str] = None
    send_by_date: Optional[str] = None
    notes: str = ""


class CampaignOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    name: str
    engagement_id: Optional[str]
    gophish_campaign_id: Optional[int]
    status: str
    template_name: str
    landing_url: str
    sent_count: int
    opened_count: int
    clicked_count: int
    submitted_count: int
    email_failed_count: int
    launched_at: Optional[datetime]
    completed_at: Optional[datetime]
    created_by: Optional[str]
    created_at: datetime
    mitre_technique: str
    notes: str
    last_synced_at: Optional[datetime]


class TargetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: str
    first_name: str
    last_name: str
    position: str
    group_name: str
    last_status: str
    opened_at: Optional[datetime]
    clicked_at: Optional[datetime]
    submitted_at: Optional[datetime]


class ResultOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    target_id: Optional[str]
    event_type: str
    ip_address: str
    user_agent: str
    payload: Optional[dict]
    ts: datetime


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _to_out(c: PhishingCampaign) -> CampaignOut:
    return CampaignOut.model_validate(c)


def _gophish_or_503() -> GoPhishClient:
    try:
        return GoPhishClient()
    except GoPhishNotConfigured as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"GoPhish not configured: {exc}",
        )


def _get_campaign_or_404(db: Session, cid: str) -> PhishingCampaign:
    c = db.get(PhishingCampaign, cid)
    if c is None:
        raise HTTPException(
            status_code=404, detail="Campaign not found"
        )
    return c


# ---------------------------------------------------------------------------
# Status
# ---------------------------------------------------------------------------


@router.get("/status")
async def get_status(
    user: User = Depends(get_current_user),
) -> dict:
    """Configure + version GoPhish."""
    client = _gophish_or_503()
    try:
        info = await client.status()
    except GoPhishError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"GoPhish unreachable: {exc}",
        )
    return {"configured": True, "info": info}


# ---------------------------------------------------------------------------
# Campaigns CRUD
# ---------------------------------------------------------------------------


@router.post(
    "/campaigns",
    response_model=CampaignOut,
    status_code=status.HTTP_201_CREATED,
)
async def create_campaign(
    payload: CreateCampaignIn,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> CampaignOut:
    """Cree group GoPhish (si targets fournis) + campagne GoPhish + persiste DB."""
    client = _gophish_or_503()

    # Validation engagement
    eng: Engagement | None = None
    if payload.engagement_id:
        eng = db.get(Engagement, payload.engagement_id)
        if eng is None:
            raise HTTPException(
                status_code=400, detail="Unknown engagement_id"
            )

    if not payload.group_name and not payload.targets:
        raise HTTPException(
            status_code=400,
            detail="Either group_name or targets[] must be provided",
        )

    group_name = payload.group_name or f"{payload.name}__group"

    # 1. Group GoPhish (cree si on a des targets)
    if payload.targets:
        gp_targets = [
            {
                "email": t.email,
                "first_name": t.first_name,
                "last_name": t.last_name,
                "position": t.position,
            }
            for t in payload.targets
        ]
        try:
            await client.create_group(group_name, gp_targets)
        except GoPhishError as exc:
            # Si le group existe deja c'est OK ; sinon on remonte
            msg = str(exc).lower()
            if "exists" not in msg and "already" not in msg:
                raise HTTPException(
                    status_code=502,
                    detail=f"GoPhish create_group failed: {exc}",
                )

    # 2. Campagne GoPhish
    gp_payload: dict = {
        "name": payload.name,
        "template": {"name": payload.template_name},
        "url": payload.landing_url,
        "smtp": {"name": payload.smtp_profile},
        "groups": [{"name": group_name}],
    }
    if payload.landing_page:
        gp_payload["page"] = {"name": payload.landing_page}
    if payload.launch_date:
        gp_payload["launch_date"] = payload.launch_date
    if payload.send_by_date:
        gp_payload["send_by_date"] = payload.send_by_date

    try:
        gp_resp = await client.create_campaign(gp_payload)
    except GoPhishError as exc:
        raise HTTPException(
            status_code=502, detail=f"GoPhish create_campaign failed: {exc}"
        )

    gp_id = gp_resp.get("id") if isinstance(gp_resp, dict) else None
    if not isinstance(gp_id, int):
        try:
            gp_id = int(gp_id) if gp_id is not None else None
        except (TypeError, ValueError):
            gp_id = None

    now = datetime.now(timezone.utc)
    launched_at = None
    if isinstance(gp_resp, dict) and gp_resp.get("launch_date"):
        try:
            launched_at = datetime.fromisoformat(
                str(gp_resp["launch_date"]).replace("Z", "+00:00")
            )
        except Exception:  # noqa: BLE001
            launched_at = now

    c = PhishingCampaign(
        id=str(uuid.uuid4()),
        name=payload.name,
        engagement_id=payload.engagement_id,
        gophish_campaign_id=gp_id,
        status="sending" if gp_id else "draft",
        template_name=payload.template_name,
        landing_url=payload.landing_url,
        sent_count=0,
        opened_count=0,
        clicked_count=0,
        submitted_count=0,
        email_failed_count=0,
        launched_at=launched_at or now,
        completed_at=None,
        created_by=user.id,
        created_at=now,
        mitre_technique="T1566.001",
        notes=payload.notes or "",
        last_synced_at=None,
    )
    db.add(c)
    db.flush()

    # 3. Persiste les targets (uniquement si on les a fournis ; sinon on
    # se basera sur la sync pour les recuperer plus tard via email).
    for t in payload.targets:
        db.add(
            PhishingTarget(
                id=str(uuid.uuid4()),
                campaign_id=c.id,
                email=t.email,
                first_name=t.first_name,
                last_name=t.last_name,
                position=t.position,
                group_name=group_name,
                last_status="pending",
            )
        )

    try:
        db.commit()
    except Exception:
        db.rollback()
        logger.exception("phishing_campaign_persist_failed")
        raise HTTPException(
            status_code=500, detail="Failed to persist campaign"
        )

    db.refresh(c)

    # 4. Audit log signe (V4.3b) + MITRE T1566.001
    try:
        record_operator_action(
            db,
            engagement_id=payload.engagement_id,
            user_id=user.id,
            action_type="phishing_launch",
            target=group_name,
            command=payload.template_name,
            result_summary=(
                f"campaign={c.id} gophish_id={gp_id} "
                f"targets={len(payload.targets)}"
            ),
        )
    except Exception:
        logger.exception("phishing_audit_failed")

    return _to_out(c)


@router.get("/campaigns", response_model=list[CampaignOut])
def list_campaigns(
    engagement_id: Optional[str] = Query(None),
    status_filter: Optional[str] = Query(None, alias="status"),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[CampaignOut]:
    q = db.query(PhishingCampaign)
    if engagement_id:
        q = q.filter(PhishingCampaign.engagement_id == engagement_id)
    if status_filter:
        q = q.filter(PhishingCampaign.status == status_filter)
    items = (
        q.order_by(desc(PhishingCampaign.created_at))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [_to_out(c) for c in items]


@router.get("/campaigns/{cid}")
def get_campaign(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    c = _get_campaign_or_404(db, cid)
    targets = [TargetOut.model_validate(t) for t in c.targets]
    last_results = (
        db.query(PhishingResult)
        .filter_by(campaign_id=cid)
        .order_by(desc(PhishingResult.ts))
        .limit(50)
        .all()
    )
    return {
        "campaign": _to_out(c).model_dump(mode="json"),
        "targets": [t.model_dump(mode="json") for t in targets],
        "results": [
            ResultOut.model_validate(r).model_dump(mode="json")
            for r in last_results
        ],
    }


@router.post("/campaigns/{cid}/sync")
async def trigger_sync(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    _get_campaign_or_404(db, cid)
    try:
        return await sync_campaign(db, cid)
    except GoPhishNotConfigured as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=str(exc),
        )
    except Exception as exc:  # noqa: BLE001
        logger.exception("phishing_sync_route_failed")
        raise HTTPException(status_code=500, detail=f"Sync failed: {exc}")


@router.delete("/campaigns/{cid}", status_code=204)
async def delete_campaign(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> None:
    if user.role != "admin":
        raise HTTPException(
            status_code=403, detail="admin role required"
        )
    c = _get_campaign_or_404(db, cid)
    gp_id = c.gophish_campaign_id

    # Best-effort: delete GoPhish-side
    if gp_id:
        try:
            client = GoPhishClient()
            await client.delete_campaign(gp_id)
        except GoPhishNotConfigured:
            logger.info(
                "phishing_delete_skipped_gophish_unconfigured",
                extra={"campaign_id": cid},
            )
        except GoPhishError as exc:
            logger.warning(
                "phishing_delete_gophish_failed",
                extra={"campaign_id": cid, "error": str(exc)},
            )

    eng_id = c.engagement_id
    db.delete(c)
    db.commit()

    try:
        record_operator_action(
            db,
            engagement_id=eng_id,
            user_id=user.id,
            action_type="phishing_delete",
            target=cid,
            command="",
            result_summary=f"deleted gophish_id={gp_id}",
        )
    except Exception:
        logger.exception("phishing_delete_audit_failed")


# ---------------------------------------------------------------------------
# Stats
# ---------------------------------------------------------------------------


def _rate(num: int, denom: int) -> float:
    if denom <= 0:
        return 0.0
    return round(num / denom, 4)


@router.get("/campaigns/{cid}/stats")
def campaign_stats(
    cid: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    c = _get_campaign_or_404(db, cid)
    total_targets = len(c.targets)
    sent = c.sent_count
    opened = c.opened_count
    clicked = c.clicked_count
    submitted = c.submitted_count
    failed = c.email_failed_count

    # base = max(sent, total_targets) pour qu'avant sync les rates restent OK
    base = max(sent, total_targets, 1)

    funnel = [
        {"stage": "sent", "count": sent},
        {"stage": "opened", "count": opened},
        {"stage": "clicked", "count": clicked},
        {"stage": "submitted", "count": submitted},
    ]

    # timeline aggregee par event_type + heure (top 50 events recents)
    rows = (
        db.query(PhishingResult)
        .filter_by(campaign_id=cid)
        .order_by(desc(PhishingResult.ts))
        .limit(200)
        .all()
    )
    timeline = [
        {
            "ts": r.ts.isoformat(),
            "event_type": r.event_type,
            "ip": r.ip_address,
        }
        for r in rows
    ]

    top_clickers = sorted(
        [
            {
                "id": t.id,
                "email": t.email,
                "name": (
                    f"{t.first_name} {t.last_name}".strip() or t.email
                ),
                "clicked_at": t.clicked_at.isoformat()
                if t.clicked_at
                else None,
                "submitted_at": t.submitted_at.isoformat()
                if t.submitted_at
                else None,
            }
            for t in c.targets
            if t.clicked_at is not None
        ],
        key=lambda x: x["clicked_at"] or "",
    )[:10]

    return {
        "campaign_id": cid,
        "total_targets": total_targets,
        "sent": sent,
        "opened": opened,
        "clicked": clicked,
        "submitted": submitted,
        "failed": failed,
        "open_rate": _rate(opened, base),
        "click_rate": _rate(clicked, base),
        "submit_rate": _rate(submitted, base),
        "fail_rate": _rate(failed, base),
        "funnel": funnel,
        "timeline": timeline,
        "top_clickers": top_clickers,
    }


# ---------------------------------------------------------------------------
# Targets / Results paginated
# ---------------------------------------------------------------------------


@router.get("/campaigns/{cid}/targets", response_model=list[TargetOut])
def list_targets(
    cid: str,
    last_status: Optional[str] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[TargetOut]:
    _get_campaign_or_404(db, cid)
    q = db.query(PhishingTarget).filter(PhishingTarget.campaign_id == cid)
    if last_status:
        q = q.filter(PhishingTarget.last_status == last_status)
    items = (
        q.order_by(PhishingTarget.email).offset(offset).limit(limit).all()
    )
    return [TargetOut.model_validate(t) for t in items]


@router.get("/campaigns/{cid}/results", response_model=list[ResultOut])
def list_results(
    cid: str,
    event_type: Optional[str] = Query(None),
    since: Optional[datetime] = Query(None),
    until: Optional[datetime] = Query(None),
    limit: int = Query(100, ge=1, le=500),
    offset: int = Query(0, ge=0),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> list[ResultOut]:
    _get_campaign_or_404(db, cid)
    if event_type and event_type not in VALID_EVENT_TYPES:
        raise HTTPException(
            status_code=400, detail=f"unknown event_type: {event_type}"
        )
    q = db.query(PhishingResult).filter(PhishingResult.campaign_id == cid)
    if event_type:
        q = q.filter(PhishingResult.event_type == event_type)
    if since:
        q = q.filter(PhishingResult.ts >= since)
    if until:
        q = q.filter(PhishingResult.ts <= until)
    items = (
        q.order_by(desc(PhishingResult.ts))
        .offset(offset)
        .limit(limit)
        .all()
    )
    return [ResultOut.model_validate(r) for r in items]


# ---------------------------------------------------------------------------
# GoPhish references (templates / groups / smtp)
# ---------------------------------------------------------------------------


@router.get("/templates")
async def list_templates(
    user: User = Depends(get_current_user),
) -> dict:
    """List templates GoPhish + builtin (best-effort sur builtin)."""
    client = _gophish_or_503()
    try:
        gp = await client.list_templates()
    except GoPhishError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"GoPhish unreachable: {exc}",
        )
    builtin: list[dict] = []
    try:
        from apps.api.pentest.post_exploit.phishing import (  # type: ignore
            BUILTIN_TEMPLATES,
        )

        builtin = [
            {"name": k, "source": "builtin", **(v if isinstance(v, dict) else {})}
            for k, v in BUILTIN_TEMPLATES.items()
        ]
    except Exception:
        builtin = []
    return {"gophish": gp, "builtin": builtin}


@router.get("/groups")
async def list_groups(
    user: User = Depends(get_current_user),
) -> list[dict]:
    client = _gophish_or_503()
    try:
        return await client.list_groups()
    except GoPhishError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"GoPhish unreachable: {exc}",
        )


@router.get("/smtp-profiles")
async def list_smtp(
    user: User = Depends(get_current_user),
) -> list[dict]:
    client = _gophish_or_503()
    try:
        return await client.list_smtp_profiles()
    except GoPhishError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"GoPhish unreachable: {exc}",
        )


@router.get("/pages")
async def list_pages(
    user: User = Depends(get_current_user),
) -> list[dict]:
    client = _gophish_or_503()
    try:
        return await client.list_pages()
    except GoPhishError as exc:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"GoPhish unreachable: {exc}",
        )
