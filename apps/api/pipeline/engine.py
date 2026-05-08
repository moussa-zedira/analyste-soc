"""Main Pipeline Engine — orchestrates event flow through all stages."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from apps.api.pipeline.config import STAGE_ORDER, PipelineConfig, get_pipeline_config
from apps.api.pipeline.context import EventContext, StageMetadata
from apps.api.pipeline.metrics import get_pipeline_metrics
from apps.api.pipeline.stages import STAGE_MAP, BaseStage

logger = logging.getLogger(__name__)


class PipelineMode(StrEnum):
    REALTIME = "realtime"
    BATCH = "batch"
    REPLAY = "replay"


# ---------------------------------------------------------------------------
# Hook registry
# ---------------------------------------------------------------------------

_pre_hooks: dict[str, list[Callable]] = {}
_post_hooks: dict[str, list[Callable]] = {}


def register_hook(
    stage_name: str,
    hook: Callable,
    *,
    pre: bool = True,
) -> None:
    """Register a pre- or post-hook on a stage.

    Hook signature: ``async hook(ctx: EventContext) -> EventContext``
    """
    target = _pre_hooks if pre else _post_hooks
    target.setdefault(stage_name, []).append(hook)


def clear_hooks() -> None:
    _pre_hooks.clear()
    _post_hooks.clear()


# ---------------------------------------------------------------------------
# Pipeline Engine
# ---------------------------------------------------------------------------

class PipelineEngine:
    """Orchestrates event processing through the full stage chain."""

    def __init__(
        self,
        config: PipelineConfig | None = None,
        mode: PipelineMode = PipelineMode.REALTIME,
    ) -> None:
        self.config = config or get_pipeline_config()
        self.mode = mode
        self._stages: list[BaseStage] = self._build_stages()
        self._semaphore = asyncio.Semaphore(self.config.max_concurrent_events)
        self.metrics = get_pipeline_metrics()

    # ------------------------------------------------------------------
    # Build stage instances
    # ------------------------------------------------------------------

    def _build_stages(self) -> list[BaseStage]:
        stages = []
        for name in STAGE_ORDER:
            cls = STAGE_MAP.get(name)
            if cls:
                stages.append(cls())
        return stages

    # ------------------------------------------------------------------
    # Process single event
    # ------------------------------------------------------------------

    async def process_event(
        self,
        raw: Any,
        *,
        dry_run: bool = False,
    ) -> EventContext:
        """Process a single event through the full pipeline.

        Returns the completed EventContext with all enrichment data.
        """
        async with self._semaphore:
            return await self._run_pipeline(raw, dry_run=dry_run)

    async def _run_pipeline(
        self,
        raw: Any,
        *,
        dry_run: bool = False,
    ) -> EventContext:
        ctx = EventContext(raw=raw, dry_run=dry_run)
        ctx.metadata["mode"] = self.mode.value
        ctx.metadata["started_at"] = datetime.now(UTC).isoformat()

        pipeline_t0 = time.monotonic()
        pipeline_success = True

        # Identify stages that can run in parallel (enrichment group)
        parallel_group = {"enrich_geo", "enrich_ti", "enrich_asset"}

        i = 0
        while i < len(self._stages):
            stage = self._stages[i]

            # Check if this is the start of the parallel enrichment group
            if (
                self.config.parallel_enrichment
                and stage.name in parallel_group
            ):
                # Collect consecutive parallel-eligible stages
                parallel_stages = []
                while i < len(self._stages) and self._stages[i].name in parallel_group:
                    if self.config.is_stage_enabled(self._stages[i].name):
                        parallel_stages.append(self._stages[i])
                    i += 1

                if parallel_stages:
                    ctx = await self._run_parallel_stages(ctx, parallel_stages)
                continue

            # Sequential stage execution
            if not self.config.is_stage_enabled(stage.name):
                sm = StageMetadata(name=stage.name, status="skipped")
                ctx.stage_meta.append(sm)
                self.metrics.record_stage(stage.name, 0, "skipped")
                i += 1
                continue

            ctx, success = await self._execute_stage(stage, ctx)
            if not success:
                pipeline_success = False
                if not self.config.continue_on_error:
                    break
            i += 1

        pipeline_elapsed = (time.monotonic() - pipeline_t0) * 1000
        ctx.metadata["finished_at"] = datetime.now(UTC).isoformat()
        ctx.metadata["total_ms"] = round(pipeline_elapsed, 2)
        ctx.metadata["success"] = pipeline_success

        self.metrics.record_pipeline(pipeline_elapsed, pipeline_success)
        return ctx

    # ------------------------------------------------------------------
    # Execute a single stage with hooks, timeout, error handling
    # ------------------------------------------------------------------

    async def _execute_stage(
        self,
        stage: BaseStage,
        ctx: EventContext,
    ) -> tuple[EventContext, bool]:
        sm = StageMetadata(
            name=stage.name,
            started_at=datetime.now(UTC),
            status="running",
        )
        ctx.stage_meta.append(sm)
        t0 = time.monotonic()

        try:
            # Pre-hooks
            for hook in _pre_hooks.get(stage.name, []):
                ctx = await hook(ctx)

            # Execute with timeout
            timeout = self.config.get_timeout(stage.name)
            ctx = await asyncio.wait_for(
                stage.execute(ctx),
                timeout=timeout,
            )

            # Post-hooks
            for hook in _post_hooks.get(stage.name, []):
                ctx = await hook(ctx)

            elapsed = (time.monotonic() - t0) * 1000
            sm.finished_at = datetime.now(UTC)
            sm.duration_ms = round(elapsed, 2)
            sm.status = "success"
            self.metrics.record_stage(stage.name, elapsed, "success")
            return ctx, True

        except TimeoutError:
            elapsed = (time.monotonic() - t0) * 1000
            sm.finished_at = datetime.now(UTC)
            sm.duration_ms = round(elapsed, 2)
            sm.status = "error"
            sm.error = f"Timeout after {self.config.get_timeout(stage.name)}s"
            self.metrics.record_stage(stage.name, elapsed, "error")
            self.metrics.record_error(
                stage.name, sm.error, ctx.parsed.get("id"),
            )
            logger.warning("Stage %s timed out", stage.name)
            return ctx, False

        except Exception as exc:
            elapsed = (time.monotonic() - t0) * 1000
            sm.finished_at = datetime.now(UTC)
            sm.duration_ms = round(elapsed, 2)
            sm.status = "error"
            sm.error = str(exc)[:500]
            self.metrics.record_stage(stage.name, elapsed, "error")
            self.metrics.record_error(
                stage.name, str(exc)[:500], ctx.parsed.get("id"),
            )
            logger.exception("Stage %s failed: %s", stage.name, exc)
            return ctx, False

    # ------------------------------------------------------------------
    # Parallel stage execution
    # ------------------------------------------------------------------

    async def _run_parallel_stages(
        self,
        ctx: EventContext,
        stages: list[BaseStage],
    ) -> EventContext:
        """Run multiple independent stages concurrently on the same context.

        Each stage gets a copy of enrichments to avoid races, then results
        are merged back.
        """

        async def _run_one(stage: BaseStage) -> tuple[str, EventContext, bool]:
            # Shallow-copy ctx for parallel execution
            local_ctx = EventContext(
                raw=ctx.raw,
                parsed=dict(ctx.parsed),
                enrichments=dict(ctx.enrichments),
                dry_run=ctx.dry_run,
                context_id=ctx.context_id,
            )
            local_ctx, success = await self._execute_stage(stage, local_ctx)
            return stage.name, local_ctx, success

        results = await asyncio.gather(
            *[_run_one(s) for s in stages],
            return_exceptions=True,
        )

        for result in results:
            if isinstance(result, Exception):
                logger.exception("Parallel stage failed: %s", result)
                continue
            stage_name, local_ctx, success = result
            # Merge enrichments back
            ctx.enrichments.update(local_ctx.enrichments)
            # Merge stage_meta
            ctx.stage_meta.extend(local_ctx.stage_meta)

        return ctx

    # ------------------------------------------------------------------
    # Batch processing
    # ------------------------------------------------------------------

    async def process_batch(
        self,
        events: list[Any],
        *,
        dry_run: bool = False,
    ) -> list[EventContext]:
        """Process a batch of events. Respects max concurrency."""
        batch_size = self.config.batch_size
        all_results: list[EventContext] = []

        for i in range(0, len(events), batch_size):
            chunk = events[i : i + batch_size]
            tasks = [
                self.process_event(raw, dry_run=dry_run)
                for raw in chunk
            ]
            results = await asyncio.gather(*tasks, return_exceptions=True)
            for r in results:
                if isinstance(r, Exception):
                    logger.exception("Batch event failed: %s", r)
                    # Create error context
                    err_ctx = EventContext()
                    err_ctx.metadata["error"] = str(r)
                    err_ctx.metadata["success"] = False
                    all_results.append(err_ctx)
                else:
                    all_results.append(r)

        return all_results

    # ------------------------------------------------------------------
    # Replay mode
    # ------------------------------------------------------------------

    async def replay(
        self,
        query: dict[str, Any] | None = None,
        time_range: tuple[datetime, datetime] | None = None,
        *,
        dry_run: bool = False,
    ) -> dict[str, Any]:
        """Re-process historical events from the database through the pipeline.

        Returns a summary dict with counts and errors.
        """
        from apps.api.db.session import SessionLocal
        from apps.api.models.event import Event

        db = SessionLocal()
        try:
            q = db.query(Event)
            if time_range:
                q = q.filter(Event.ts >= time_range[0], Event.ts <= time_range[1])
            if query:
                if query.get("event_type"):
                    q = q.filter(Event.event_type == query["event_type"])
                if query.get("severity"):
                    q = q.filter(Event.severity == query["severity"])
                if query.get("source"):
                    q = q.filter(Event.source == query["source"])

            events = q.order_by(Event.ts.asc()).limit(10000).all()

            raw_events = []
            for evt in events:
                raw_events.append({
                    "id": evt.id,
                    "ts": evt.ts,
                    "source": evt.source,
                    "event_type": evt.event_type,
                    "severity": evt.severity,
                    "src_ip": evt.src_ip,
                    "dst_ip": evt.dst_ip,
                    "username": evt.username,
                    "message": evt.message,
                    "raw": evt.raw,
                })
        finally:
            db.close()

        # Switch to replay mode
        original_mode = self.mode
        self.mode = PipelineMode.REPLAY
        try:
            results = await self.process_batch(raw_events, dry_run=dry_run)
        finally:
            self.mode = original_mode

        successes = sum(
            1 for r in results if r.metadata.get("success", False)
        )
        return {
            "total": len(results),
            "success": successes,
            "errors": len(results) - successes,
            "mode": "replay",
            "dry_run": dry_run,
        }

    # ------------------------------------------------------------------
    # Introspection
    # ------------------------------------------------------------------

    def get_stages_info(self) -> list[dict[str, Any]]:
        """Return information about all stages."""
        info = []
        for stage in self._stages:
            info.append({
                "name": stage.name,
                "enabled": self.config.is_stage_enabled(stage.name),
                "timeout_seconds": self.config.get_timeout(stage.name),
                "class": stage.__class__.__name__,
            })
        return info


# ---------------------------------------------------------------------------
# Singleton engine instance
# ---------------------------------------------------------------------------

_engine_instance: PipelineEngine | None = None


def get_pipeline_engine() -> PipelineEngine:
    global _engine_instance
    if _engine_instance is None:
        _engine_instance = PipelineEngine()
    return _engine_instance
