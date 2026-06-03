"""Routes /redteam/reporting (V4.3c) — JSON aggregated + PDF stream + catalog."""

from __future__ import annotations

import io
import logging
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse
from sqlalchemy.orm import Session

from apps.api.auth import get_current_user
from apps.api.db.session import get_db
from apps.api.models.user import User
from apps.api.pentest.reporting.aggregator import (
    build_engagement_report_data,
    load_mitre_catalog,
)
from apps.api.pentest.reporting.pdf_report import generate_engagement_pdf

logger = logging.getLogger("apps.api.pentest.reporting")
router = APIRouter(prefix="/redteam/reporting", tags=["Red Team Reporting"])


@router.get("/mitre/catalog")
def get_mitre_catalog(user: User = Depends(get_current_user)) -> dict:
    return load_mitre_catalog()


@router.get("/engagements/{engagement_id}/data")
async def get_engagement_data(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    try:
        return await build_engagement_report_data(db, engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    except Exception:  # noqa: BLE001
        logger.exception("redteam_report_data_failed")
        raise HTTPException(status_code=500, detail="Failed to build report")


@router.get("/engagements/{engagement_id}/kill-chain")
async def get_engagement_kill_chain(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    try:
        data = await build_engagement_report_data(db, engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    return {
        "engagement_id": engagement_id,
        "in_scope_pct": data["in_scope_pct"],
        "total_actions": data["total_actions"],
        "kill_chain": data["kill_chain"],
    }


@router.get("/engagements/{engagement_id}/pdf")
async def get_engagement_pdf(
    engagement_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> StreamingResponse:
    try:
        data = await build_engagement_report_data(db, engagement_id)
    except ValueError as e:
        raise HTTPException(status_code=404, detail=str(e))
    catalog = load_mitre_catalog()
    try:
        pdf_bytes = generate_engagement_pdf(data, catalog=catalog)
    except Exception:  # noqa: BLE001
        logger.exception("redteam_pdf_generate_failed")
        raise HTTPException(status_code=500, detail="PDF generation failed")

    client = (data.get("engagement", {}).get("client_name") or "client").replace(" ", "_")
    date = datetime.now(UTC).strftime("%Y%m%d")
    filename = f"redteam_report_{client}_{date}.pdf"
    headers = {"Content-Disposition": f"attachment; filename={filename}"}
    return StreamingResponse(
        io.BytesIO(pdf_bytes),
        media_type="application/pdf",
        headers=headers,
    )
