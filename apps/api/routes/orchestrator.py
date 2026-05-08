"""Pentest Orchestrator API — REST + WebSocket endpoints.

Endpoints:
  POST /orchestrator/start            — start orchestration
  GET  /orchestrator/status/{id}      — get status + progress
  GET  /orchestrator/results/{id}     — get full results
  POST /orchestrator/pause/{id}       — pause orchestration
  POST /orchestrator/resume/{id}      — resume orchestration
  POST /orchestrator/cancel/{id}      — cancel orchestration
  GET  /orchestrator/findings/{id}    — get aggregated findings with SARIF
  GET  /orchestrator/report/{id}      — get generated report
  GET  /orchestrator/timeline/{id}    — get action timeline
  GET  /orchestrator/profiles         — list available scan profiles
  GET  /orchestrator/history          — list past orchestrations
  WS   /ws/orchestrator/{id}          — real-time progress updates
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from fastapi import APIRouter, Depends, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from apps.api.security import require_api_key

router = APIRouter(
    prefix="/orchestrator",
    tags=["Pentest Orchestrator"],
    dependencies=[Depends(require_api_key)],
)
ws_router = APIRouter(tags=["Orchestrator WebSocket"])
logger = logging.getLogger(__name__)

# In-memory registry of running orchestrations
_running: dict[str, Any] = {}


# ── Helpers ────────────────────────────────────────────────────────────────


def _resolve_state(orch_id: str):
    """Resolve orchestration state from memory, Redis, or DB."""
    from apps.api.pentest.orchestrator.state import StatePersistence

    orch = _running.get(orch_id)
    if orch:
        return orch, orch.state

    state = StatePersistence.load_from_redis(orch_id)
    if state:
        return None, state

    state = StatePersistence.load_from_db(orch_id)
    if state:
        return None, state

    return None, None


# ── Schemas ────────────────────────────────────────────────────────────────


class StartRequest(BaseModel):
    target: str = Field(..., description="Target URL, IP, or domain")
    profile: str = Field(
        "full_pentest",
        description="quick_recon, web_full, network_full, stealth, full_pentest, red_team, api_audit, custom",
    )
    scope: list[str] = Field(default_factory=list, description="Authorized scope (IPs, CIDRs, domains)")
    options: dict[str, Any] = Field(default_factory=dict)
    custom_phases: list[str] = Field(
        default_factory=list,
        description="For custom profile: recon, vuln_assessment, exploitation, post_exploitation, reporting",
    )


# ── Launch ─────────────────────────────────────────────────────────────────


@router.post("/start", summary="Start a pentest orchestration")
async def start_orchestration(body: StartRequest):
    """Launch a new pentest orchestration against a target.

    The orchestration runs in the background and chains all pentest tools
    automatically through the selected profile phases.
    """
    from apps.api.pentest.orchestrator.engine import PentestOrchestrator
    from apps.api.pentest.orchestrator.state import Phase, ScanProfile, StatePersistence

    try:
        profile = ScanProfile(body.profile)
    except ValueError:
        raise HTTPException(400, f"Invalid profile: {body.profile}. Valid: {[p.value for p in ScanProfile]}")

    # Validate custom phases
    custom_phases = None
    if profile == ScanProfile.CUSTOM:
        if not body.custom_phases:
            raise HTTPException(400, "custom_phases required when profile=custom")
        custom_phases = []
        for p in body.custom_phases:
            try:
                custom_phases.append(Phase(p))
            except ValueError:
                raise HTTPException(400, f"Invalid phase '{p}'. Valid: {[ph.value for ph in Phase]}")

    scope = body.scope if body.scope else [body.target]

    orch = PentestOrchestrator(
        target=body.target,
        profile=profile,
        scope=scope,
        options=body.options,
        custom_phases=custom_phases,
    )

    _running[orch.state.id] = orch

    async def _run_and_cleanup():
        try:
            await orch.run()
        except Exception as exc:
            logger.exception("Orchestration %s failed: %s", orch.state.id, exc)
        finally:
            StatePersistence.save_to_db(orch.state)

    asyncio.create_task(_run_and_cleanup())

    return {
        "id": orch.state.id,
        "target": body.target,
        "profile": body.profile,
        "status": "running",
        "message": f"Orchestration started. Track at GET /orchestrator/status/{orch.state.id}",
    }


# Also keep /launch as alias for backward compatibility
@router.post("/launch", summary="Launch orchestration (alias for /start)")
async def launch_orchestration(body: StartRequest):
    """Alias for /start — backward compatibility."""
    return await start_orchestration(body)


# ── Status & Results ───────────────────────────────────────────────────────


@router.get("/status/{orch_id}", summary="Get orchestration status and progress")
async def get_status(orch_id: str):
    """Get current status, phase, progress, and counts."""
    _, state = _resolve_state(orch_id)
    if not state:
        raise HTTPException(404, "Orchestration not found")
    return state.summary()


@router.get("/results/{orch_id}", summary="Get full orchestration results")
async def get_results(orch_id: str):
    """Get complete results including all discovered data, vulns, exploits."""
    _, state = _resolve_state(orch_id)
    if not state:
        raise HTTPException(404, "Orchestration not found")
    return state.to_dict()


# ── Control ────────────────────────────────────────────────────────────────


@router.post("/pause/{orch_id}", summary="Pause orchestration")
async def pause_orchestration(orch_id: str):
    """Pause a running orchestration. Can be resumed later."""
    orch = _running.get(orch_id)
    if not orch:
        raise HTTPException(404, "Orchestration not found or not running")
    orch.pause()
    return {"id": orch_id, "status": "paused"}


@router.post("/resume/{orch_id}", summary="Resume paused orchestration")
async def resume_orchestration(orch_id: str):
    """Resume a previously paused orchestration."""
    orch = _running.get(orch_id)
    if not orch:
        raise HTTPException(404, "Orchestration not found or not running")
    orch.resume()
    return {"id": orch_id, "status": "running"}


@router.post("/cancel/{orch_id}", summary="Cancel orchestration")
async def cancel_orchestration(orch_id: str):
    """Cancel a running or paused orchestration."""
    orch = _running.get(orch_id)
    if not orch:
        raise HTTPException(404, "Orchestration not found or not running")
    orch.cancel()
    return {"id": orch_id, "status": "cancelled"}


# ── Findings ───────────────────────────────────────────────────────────────


@router.get("/findings/{orch_id}", summary="Get aggregated findings with enrichment")
async def get_findings(orch_id: str):
    """Get aggregated, deduplicated, enriched findings with SARIF export."""
    from apps.api.pentest.orchestrator.findings import FindingsAggregator

    _, state = _resolve_state(orch_id)
    if not state:
        raise HTTPException(404, "Orchestration not found")

    aggregator = FindingsAggregator(state)
    findings = aggregator.aggregate()

    return {
        "id": orch_id,
        "total_findings": len(findings),
        "risk_score": aggregator.overall_risk_score(),
        "severity_distribution": aggregator.severity_distribution(),
        "owasp_distribution": aggregator.owasp_distribution(),
        "mitre_tactics": aggregator.mitre_tactics(),
        "attack_surface": aggregator.attack_surface_summary(),
        "findings": findings,
        "sarif": aggregator.to_sarif(),
    }


# ── Report ─────────────────────────────────────────────────────────────────


@router.get("/report/{orch_id}", summary="Get auto-generated pentest report")
async def get_report(orch_id: str):
    """Get the complete pentest report (structured JSON for frontend rendering)."""
    from apps.api.pentest.orchestrator.report_gen import ReportGenerator

    _, state = _resolve_state(orch_id)
    if not state:
        raise HTTPException(404, "Orchestration not found")

    if state.report:
        return state.report

    # Generate on demand
    gen = ReportGenerator(state)
    return gen.generate()


# ── Timeline ───────────────────────────────────────────────────────────────


@router.get("/timeline/{orch_id}", summary="Get chronological action timeline")
async def get_timeline(orch_id: str, limit: int = 500):
    """Get chronological timeline of all actions, errors, and metrics."""
    _, state = _resolve_state(orch_id)
    if not state:
        raise HTTPException(404, "Orchestration not found")

    return {
        "id": orch_id,
        "total_events": len(state.timeline),
        "timeline": state.timeline[-limit:],
        "errors": state.errors,
        "phase_metrics": state.phase_metrics,
        "tool_metrics": state.tool_metrics,
    }


# ── Listing ────────────────────────────────────────────────────────────────


@router.get("/profiles", summary="List available scan profiles")
async def list_profiles():
    """List all available scan profiles with descriptions and phases."""
    from apps.api.pentest.orchestrator.state import (
        PROFILE_DESCRIPTIONS,
        PROFILE_PHASES,
        ScanProfile,
    )

    return {
        "profiles": [
            {
                "id": p.value,
                "name": p.value.replace("_", " ").title(),
                "description": PROFILE_DESCRIPTIONS.get(p, ""),
                "phases": [ph.value for ph in PROFILE_PHASES.get(p, [])],
            }
            for p in ScanProfile
        ],
    }


# Keep old path as alias
@router.get("/profiles/list", summary="List profiles (alias)")
async def list_profiles_alias():
    return await list_profiles()


@router.get("/history", summary="List past orchestrations")
async def list_history(limit: int = 50):
    """List active and past orchestration runs."""
    from apps.api.pentest.orchestrator.state import StatePersistence

    active = [orch.state.summary() for orch in _running.values()]
    history = StatePersistence.list_history(limit=limit)

    return {"active": active, "history": history}


# Keep root listing
@router.get("/", summary="List orchestrations")
async def list_orchestrations():
    return await list_history()


# Legacy detail endpoint
@router.get("/{orch_id}", summary="Get full orchestration state")
async def get_orchestration_detail(orch_id: str):
    """Get full state of an orchestration (alias for /results)."""
    return await get_results(orch_id)


@router.get("/{orch_id}/summary", summary="Get compact summary")
async def get_summary(orch_id: str):
    return await get_status(orch_id)


# ═══════════════════════════════════════════════════════════════════════════
# WEBSOCKET — Real-time progress updates
# ═══════════════════════════════════════════════════════════════════════════


@ws_router.websocket("/ws/orchestrator/{orch_id}")
async def orchestrator_ws(websocket: WebSocket, orch_id: str):
    """WebSocket for real-time orchestration progress.

    Sends JSON messages every 2s with status, progress, stats, and new events.
    Closes when orchestration completes, fails, or is cancelled.
    """
    await websocket.accept()

    try:
        last_event_idx = 0

        while True:
            _, state = _resolve_state(orch_id)
            if not state:
                await websocket.send_json({"type": "error", "message": "Orchestration not found"})
                break

            msg: dict[str, Any] = {
                "type": "progress",
                "id": orch_id,
                "status": state.status,
                "phase": state.phase,
                "progress": state.progress,
                "stats": {
                    "hosts": len(state.discovered_hosts),
                    "urls": len(state.discovered_urls),
                    "subdomains": len(state.discovered_subdomains),
                    "vulns": len(state.vulnerabilities),
                    "exploits": len(state.exploits_succeeded),
                    "creds": len(state.credentials_found),
                    "errors": len(state.errors),
                },
            }

            # Stream new timeline events
            current_count = len(state.timeline)
            if current_count > last_event_idx:
                msg["new_events"] = state.timeline[last_event_idx:]
                last_event_idx = current_count

            await websocket.send_json(msg)

            # Complete
            if state.status in ("completed", "failed", "cancelled"):
                await websocket.send_json({
                    "type": "complete",
                    "id": orch_id,
                    "status": state.status,
                    "summary": state.summary(),
                })
                break

            await asyncio.sleep(2)

    except WebSocketDisconnect:
        pass
    except Exception:
        try:
            await websocket.close()
        except Exception:
            logger.debug("orchestrator: ignored exception", exc_info=True)
