"""Pipeline API — status, metrics, configuration, ingestion, and replay endpoints."""

from __future__ import annotations

import logging
from datetime import datetime
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/pipeline", tags=["Pipeline"])


# ---------------------------------------------------------------------------
# Request / response schemas
# ---------------------------------------------------------------------------


class IngestRequest(BaseModel):
    events: list[Any] = Field(..., description="Raw events (strings or dicts)")


class ReplayRequest(BaseModel):
    query: dict[str, Any] | None = Field(None, description="Filter: event_type, severity, source")
    start_time: str | None = Field(None, description="ISO datetime start")
    end_time: str | None = Field(None, description="ISO datetime end")
    dry_run: bool = False


class TestRequest(BaseModel):
    event: Any = Field(..., description="Single raw event (string or dict)")


class ConfigUpdateRequest(BaseModel):
    stages: dict[str, dict[str, Any]] | None = None
    batch_size: int | None = None
    max_concurrent_events: int | None = None
    ml_classification_enabled: bool | None = None
    ti_providers: list[str] | None = None
    alert_channels: dict[str, list[str]] | None = None
    continue_on_error: bool | None = None
    parallel_enrichment: bool | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.get("/status")
async def pipeline_status() -> dict[str, Any]:
    """Pipeline health, stage status, and throughput."""
    from apps.api.pipeline.metrics import get_pipeline_metrics

    metrics = get_pipeline_metrics()
    return metrics.get_health()


@router.get("/metrics")
async def pipeline_metrics() -> dict[str, Any]:
    """Detailed per-stage metrics."""
    from apps.api.pipeline.metrics import get_pipeline_metrics

    metrics = get_pipeline_metrics()
    return {
        "overall": metrics.get_overall_metrics(),
        "stages": metrics.get_stage_metrics(),
    }


@router.get("/config")
async def pipeline_config() -> dict[str, Any]:
    """Current pipeline configuration."""
    from apps.api.pipeline.config import get_pipeline_config

    return get_pipeline_config().to_dict()


@router.put("/config")
async def update_config(body: ConfigUpdateRequest) -> dict[str, Any]:
    """Update pipeline configuration (partial)."""
    from apps.api.pipeline.config import update_pipeline_config

    updates = body.model_dump(exclude_none=True)
    cfg = update_pipeline_config(updates)
    return {"status": "updated", "config": cfg.to_dict()}


@router.post("/ingest")
async def ingest_events(body: IngestRequest) -> dict[str, Any]:
    """Manually ingest event(s) into the pipeline."""
    from apps.api.pipeline.engine import get_pipeline_engine

    engine = get_pipeline_engine()
    results = await engine.process_batch(body.events)

    successes = sum(1 for r in results if r.metadata.get("success", False))
    return {
        "total": len(results),
        "success": successes,
        "errors": len(results) - successes,
        "results": [r.to_dict() for r in results[:50]],  # cap response size
    }


@router.post("/replay")
async def replay_events(body: ReplayRequest) -> dict[str, Any]:
    """Replay historical events through the pipeline."""
    from apps.api.pipeline.engine import get_pipeline_engine

    engine = get_pipeline_engine()

    time_range = None
    if body.start_time and body.end_time:
        try:
            start = datetime.fromisoformat(body.start_time.replace("Z", "+00:00"))
            end = datetime.fromisoformat(body.end_time.replace("Z", "+00:00"))
            time_range = (start, end)
        except ValueError:
            raise HTTPException(400, "Invalid time format. Use ISO 8601.")

    result = await engine.replay(
        query=body.query,
        time_range=time_range,
        dry_run=body.dry_run,
    )
    return result


@router.post("/test")
async def test_pipeline(body: TestRequest) -> dict[str, Any]:
    """Dry-run a single event through the pipeline. Returns enrichment results."""
    from apps.api.pipeline.engine import get_pipeline_engine

    engine = get_pipeline_engine()
    ctx = await engine.process_event(body.event, dry_run=True)
    return ctx.to_dict()


@router.get("/stages")
async def list_stages() -> list[dict[str, Any]]:
    """List all pipeline stages with status."""
    from apps.api.pipeline.engine import get_pipeline_engine

    engine = get_pipeline_engine()
    return engine.get_stages_info()


@router.put("/stages/{name}/toggle")
async def toggle_stage(name: str) -> dict[str, Any]:
    """Enable or disable a specific pipeline stage."""
    from apps.api.pipeline.config import STAGE_ORDER, StageConfig, get_pipeline_config

    if name not in STAGE_ORDER:
        raise HTTPException(404, f"Stage '{name}' not found")

    cfg = get_pipeline_config()
    if name not in cfg.stages:
        cfg.stages[name] = StageConfig()

    cfg.stages[name].enabled = not cfg.stages[name].enabled
    return {
        "stage": name,
        "enabled": cfg.stages[name].enabled,
    }


@router.get("/errors")
async def pipeline_errors(limit: int = 50) -> list[dict[str, Any]]:
    """Recent pipeline processing errors."""
    from apps.api.pipeline.metrics import get_pipeline_metrics

    metrics = get_pipeline_metrics()
    return metrics.get_recent_errors(limit=limit)


@router.get("/bottlenecks")
async def pipeline_bottlenecks() -> list[dict[str, Any]]:
    """Performance analysis — stages sorted by average duration."""
    from apps.api.pipeline.metrics import get_pipeline_metrics

    metrics = get_pipeline_metrics()
    return metrics.get_bottlenecks()
