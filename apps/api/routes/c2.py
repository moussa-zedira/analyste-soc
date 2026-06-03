"""Routes Sliver C2 (V4.3a) — wrapping vanilla des operations Sliver.

Toutes les routes sont protegees par get_current_user. Les exceptions
RuntimeError (lib absente / cfg manquante / Sliver server down) sont
traduites en HTTP 503.

V4.3b ajoute le parametre engagement_id obligatoire sur les endpoints
qui executent (exec / kill / generate) et appelle assert_engagement_allows
+ ecrit un OperatorAuditLog signe.
"""

from __future__ import annotations

import logging
import uuid
from datetime import UTC, datetime

from fastapi import APIRouter, Depends, HTTPException, Query, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.auth import get_current_user
from apps.api.db.session import get_db
from apps.api.models.sliver import (
    SliverCommand,
    SliverImplantBuild,
    SliverSession,
)
from apps.api.models.user import User
from apps.api.pentest.c2_sliver import client as sliver_client

logger = logging.getLogger("apps.api.pentest.c2_sliver")
router = APIRouter(prefix="/redteam/c2", tags=["Red Team C2"])


# ---------------------------------------------------------------------------
# Pydantic schemas
# ---------------------------------------------------------------------------


class StatusResponse(BaseModel):
    configured: bool
    available: bool
    sessions_count: int = 0
    beacons_count: int = 0
    server_version: dict | None = None
    error: str | None = None


class ExecRequest(BaseModel):
    command: str = Field(min_length=1, max_length=4096)
    timeout: int = Field(default=30, ge=1, le=600)


class GenerateImplantRequest(BaseModel):
    name: str = Field(min_length=1, max_length=128)
    os: str = Field(description="windows | linux | darwin")
    arch: str = Field(description="amd64 | 386 | arm64")
    format: str = Field(description="EXECUTABLE | SHARED_LIB | SHELLCODE | SERVICE")
    c2_url: str = Field(min_length=1)
    sleep: int = Field(default=60, ge=1, le=86400)
    jitter: int = Field(default=20, ge=0, le=100)


# ---------------------------------------------------------------------------
# Engagement guard hook (V4.3b) — soft dependency
# ---------------------------------------------------------------------------


async def _engagement_guard(db: Session, engagement_id: str | None, target: str | None) -> None:
    """Si V4.3b est disponible, applique assert_engagement_allows."""
    try:
        from apps.api.pentest.engagement.guard import assert_engagement_allows
    except Exception:  # noqa: BLE001
        return  # V4.3b pas encore deploye -> pas de garde
    if engagement_id:
        await assert_engagement_allows(db, engagement_id, target)


def _record_audit(
    db: Session,
    *,
    engagement_id: str | None,
    user_id: str | None,
    action_type: str,
    target: str,
    command: str,
    result_summary: str,
) -> None:
    """Si V4.3b est disponible, ecrit un OperatorAuditLog signe."""
    try:
        from apps.api.pentest.engagement.audit import record_operator_action
    except Exception:  # noqa: BLE001
        return
    try:
        record_operator_action(
            db,
            engagement_id=engagement_id,
            user_id=user_id,
            action_type=action_type,
            target=target,
            command=command,
            result_summary=result_summary,
        )
    except Exception:  # noqa: BLE001
        logger.exception("audit_record_failed")


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------


@router.get("/status", response_model=StatusResponse)
async def c2_status(
    user: User = Depends(get_current_user),
) -> StatusResponse:
    """Etat de la connexion Sliver. 503 si non configure."""
    try:
        version = await sliver_client.get_server_version()
        sessions = await sliver_client.list_sessions()
        beacons = await sliver_client.list_beacons()
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("c2_status_failed")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Sliver server unreachable",
        )
    return StatusResponse(
        configured=True,
        available=True,
        sessions_count=len(sessions),
        beacons_count=len(beacons),
        server_version=version,
    )


@router.get("/sessions")
async def list_sessions_route(
    user: User = Depends(get_current_user),
) -> list[dict]:
    try:
        return await sliver_client.list_sessions()
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("c2_sessions_failed")
        raise HTTPException(status_code=502, detail="Sliver server unreachable")


@router.get("/sessions/{session_id}")
async def get_session_route(
    session_id: str,
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    try:
        sess = await sliver_client.get_session(session_id)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("c2_session_get_failed")
        raise HTTPException(status_code=502, detail="Sliver server unreachable")
    if sess is None:
        raise HTTPException(status_code=404, detail="Session not found")

    last_cmds = (
        db.query(SliverCommand)
        .filter(SliverCommand.session_id == session_id)
        .order_by(SliverCommand.executed_at.desc())
        .limit(20)
        .all()
    )
    sess["recent_commands"] = [
        {
            "id": c.id,
            "command": c.command,
            "status": c.status,
            "executed_at": c.executed_at.isoformat() if c.executed_at else None,
            "duration_ms": c.duration_ms,
        }
        for c in last_cmds
    ]
    return sess


@router.delete("/sessions/{session_id}")
async def kill_session_route(
    session_id: str,
    engagement_id: str = Query(..., description="ID de l'engagement actif"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    target_label = session_id
    await _engagement_guard(db, engagement_id, target_label)
    try:
        result = await sliver_client.kill_session(session_id)
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("c2_kill_failed")
        raise HTTPException(status_code=502, detail="Sliver kill failed")

    # Marque la session locale comme inactive si elle existe
    sess = db.get(SliverSession, session_id)
    if sess is not None:
        sess.active = False
        db.add(sess)
        db.commit()

    _record_audit(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="c2_kill",
        target=target_label,
        command="kill",
        result_summary="killed",
    )
    return result


@router.post("/sessions/{session_id}/exec")
async def exec_command_route(
    session_id: str,
    payload: ExecRequest,
    engagement_id: str = Query(..., description="ID de l'engagement actif"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    target_label = session_id
    await _engagement_guard(db, engagement_id, target_label)

    started = datetime.now(UTC)
    try:
        result = await sliver_client.execute_command(
            session_id, payload.command, timeout=payload.timeout
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("c2_exec_failed")
        raise HTTPException(status_code=502, detail="Sliver exec failed")
    completed = datetime.now(UTC)
    duration_ms = int((completed - started).total_seconds() * 1000)

    # Persiste la session si premiere fois
    sess = db.get(SliverSession, session_id)
    if sess is None:
        sess = SliverSession(
            id=session_id,
            name="",
            hostname="",
            username="",
            os="",
            arch="",
            transport="",
            remote_address="",
            pid=0,
            active=True,
            engagement_id=engagement_id,
        )
        db.add(sess)
        try:
            db.commit()
        except Exception:  # noqa: BLE001
            db.rollback()

    cmd = SliverCommand(
        id=str(uuid.uuid4()),
        session_id=session_id,
        engagement_id=engagement_id,
        command=payload.command,
        output=(result.get("stdout", "") or "")
        + (("\n" + result["stderr"]) if result.get("stderr") else ""),
        status="ok" if int(result.get("status", 0) or 0) == 0 else "error",
        executed_by=user.id,
        executed_at=started,
        completed_at=completed,
        duration_ms=duration_ms,
    )
    db.add(cmd)
    try:
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()

    _record_audit(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="c2_exec",
        target=target_label,
        command=payload.command,
        result_summary=f"status={result.get('status')} dur_ms={duration_ms}",
    )

    return {
        "command_id": cmd.id,
        "session_id": session_id,
        "engagement_id": engagement_id,
        "duration_ms": duration_ms,
        **result,
    }


@router.get("/beacons")
async def list_beacons_route(
    user: User = Depends(get_current_user),
) -> list[dict]:
    try:
        return await sliver_client.list_beacons()
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception:  # noqa: BLE001
        logger.exception("c2_beacons_failed")
        raise HTTPException(status_code=502, detail="Sliver server unreachable")


@router.get("/implants")
async def list_implants_route(
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    """Combine la liste DB locale + la liste cote Sliver server."""
    local = (
        db.query(SliverImplantBuild).order_by(SliverImplantBuild.created_at.desc()).limit(200).all()
    )
    local_list = [
        {
            "id": b.id,
            "name": b.name,
            "os": b.os,
            "arch": b.arch,
            "format": b.format,
            "c2_url": b.c2_url,
            "sleep_seconds": b.sleep_seconds,
            "jitter_pct": b.jitter_pct,
            "build_path": b.build_path,
            "size_bytes": b.size_bytes,
            "engagement_id": b.engagement_id,
            "created_at": b.created_at.isoformat() if b.created_at else None,
        }
        for b in local
    ]
    server_list: list[dict] = []
    try:
        server_list = await sliver_client.list_implant_builds()
    except RuntimeError:
        pass  # pas configure -> on retourne juste la DB locale
    except Exception:  # noqa: BLE001
        logger.exception("c2_implants_server_failed")

    return {
        "local_builds": local_list,
        "server_builds": server_list,
    }


@router.post("/implants/generate")
async def generate_implant_route(
    payload: GenerateImplantRequest,
    engagement_id: str = Query(..., description="ID de l'engagement actif"),
    db: Session = Depends(get_db),
    user: User = Depends(get_current_user),
) -> dict:
    target_label = payload.c2_url
    await _engagement_guard(db, engagement_id, target_label)
    try:
        result = await sliver_client.generate_implant(
            name=payload.name,
            os=payload.os,
            arch=payload.arch,
            format=payload.format,
            c2_url=payload.c2_url,
            sleep=payload.sleep,
            jitter=payload.jitter,
        )
    except RuntimeError as e:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail=f"Sliver C2 not configured: {e}",
        )
    except Exception as e:  # noqa: BLE001
        logger.exception("c2_implant_generate_failed")
        raise HTTPException(status_code=502, detail=f"Sliver generate failed: {e}")

    build = SliverImplantBuild(
        id=result["id"],
        name=result["name"],
        os=result["os"],
        arch=result["arch"],
        format=result["format"],
        c2_url=result["c2_url"],
        sleep_seconds=result["sleep_seconds"],
        jitter_pct=result["jitter_pct"],
        build_path=result.get("build_path"),
        size_bytes=int(result.get("size_bytes", 0) or 0),
        engagement_id=engagement_id,
        created_at=datetime.now(UTC),
        created_by=user.id,
    )
    db.add(build)
    try:
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()

    _record_audit(
        db,
        engagement_id=engagement_id,
        user_id=user.id,
        action_type="implant_build",
        target=target_label,
        command=f"generate {payload.os}/{payload.arch} {payload.format}",
        result_summary=f"build_id={build.id} size={build.size_bytes}",
    )
    return result
