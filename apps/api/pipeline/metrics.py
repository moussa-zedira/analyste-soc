"""Pipeline Metrics & Monitoring — per-stage and overall pipeline metrics."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# In-memory metrics (always available)
# ---------------------------------------------------------------------------


@dataclass
class _StageStats:
    """Running statistics for one stage."""

    count: int = 0
    success: int = 0
    error: int = 0
    skipped: int = 0
    total_ms: float = 0.0
    max_ms: float = 0.0
    # Keep last N durations for percentile calculation
    _durations: list[float] = field(default_factory=list)
    _MAX_DURATIONS: int = 1000

    def record(self, duration_ms: float, status: str) -> None:
        self.count += 1
        self.total_ms += duration_ms
        if duration_ms > self.max_ms:
            self.max_ms = duration_ms
        if status == "success":
            self.success += 1
        elif status == "error":
            self.error += 1
        elif status == "skipped":
            self.skipped += 1
        self._durations.append(duration_ms)
        if len(self._durations) > self._MAX_DURATIONS:
            self._durations = self._durations[-self._MAX_DURATIONS:]

    @property
    def avg_ms(self) -> float:
        return self.total_ms / self.count if self.count else 0.0

    @property
    def error_rate(self) -> float:
        return self.error / self.count if self.count else 0.0

    def percentile(self, p: float) -> float:
        if not self._durations:
            return 0.0
        sorted_d = sorted(self._durations)
        idx = int(len(sorted_d) * p / 100.0)
        idx = min(idx, len(sorted_d) - 1)
        return sorted_d[idx]

    @property
    def health(self) -> str:
        if self.count == 0:
            return "idle"
        if self.error_rate > 0.5:
            return "failed"
        if self.error_rate > 0.1:
            return "degraded"
        return "healthy"


class PipelineMetrics:
    """Collects and serves pipeline metrics."""

    def __init__(self) -> None:
        self._stages: dict[str, _StageStats] = defaultdict(_StageStats)
        self._pipeline_count: int = 0
        self._pipeline_errors: int = 0
        self._pipeline_total_ms: float = 0.0
        self._start_time: float = time.time()
        # Throughput tracking: list of (timestamp, count) tuples
        self._throughput_log: list[tuple[float, int]] = []
        # Recent errors for debugging
        self._recent_errors: list[dict[str, Any]] = []
        self._MAX_ERRORS = 100

    # ------------------------------------------------------------------
    # Recording
    # ------------------------------------------------------------------

    def record_stage(self, stage_name: str, duration_ms: float, status: str) -> None:
        self._stages[stage_name].record(duration_ms, status)
        self._try_push_redis(stage_name, duration_ms, status)

    def record_pipeline(self, duration_ms: float, success: bool) -> None:
        self._pipeline_count += 1
        self._pipeline_total_ms += duration_ms
        if not success:
            self._pipeline_errors += 1
        self._throughput_log.append((time.time(), 1))
        # Trim old entries (keep last hour)
        cutoff = time.time() - 3600
        self._throughput_log = [
            (ts, c) for ts, c in self._throughput_log if ts > cutoff
        ]

    def record_error(self, stage_name: str, error: str, event_id: str | None = None) -> None:
        entry = {
            "stage": stage_name,
            "error": error[:500],
            "event_id": event_id,
            "timestamp": time.time(),
        }
        self._recent_errors.append(entry)
        if len(self._recent_errors) > self._MAX_ERRORS:
            self._recent_errors = self._recent_errors[-self._MAX_ERRORS:]

    # ------------------------------------------------------------------
    # Querying
    # ------------------------------------------------------------------

    def get_stage_metrics(self) -> dict[str, Any]:
        result = {}
        for name, stats in self._stages.items():
            result[name] = {
                "count": stats.count,
                "success": stats.success,
                "error": stats.error,
                "skipped": stats.skipped,
                "avg_ms": round(stats.avg_ms, 2),
                "p95_ms": round(stats.percentile(95), 2),
                "p99_ms": round(stats.percentile(99), 2),
                "max_ms": round(stats.max_ms, 2),
                "error_rate": round(stats.error_rate, 4),
                "health": stats.health,
            }
        return result

    def get_overall_metrics(self) -> dict[str, Any]:
        now = time.time()
        # Events per minute (last 60s)
        one_min_ago = now - 60
        epm = sum(c for ts, c in self._throughput_log if ts > one_min_ago)
        # Events per hour
        eph = sum(c for _, c in self._throughput_log)

        return {
            "total_events": self._pipeline_count,
            "total_errors": self._pipeline_errors,
            "avg_processing_ms": round(
                self._pipeline_total_ms / self._pipeline_count, 2
            ) if self._pipeline_count else 0.0,
            "error_rate": round(
                self._pipeline_errors / self._pipeline_count, 4
            ) if self._pipeline_count else 0.0,
            "events_per_minute": epm,
            "events_per_hour": eph,
            "uptime_seconds": round(now - self._start_time, 1),
        }

    def get_bottlenecks(self) -> list[dict[str, Any]]:
        """Return stages sorted by average duration (slowest first)."""
        stages = []
        for name, stats in self._stages.items():
            if stats.count == 0:
                continue
            stages.append({
                "stage": name,
                "avg_ms": round(stats.avg_ms, 2),
                "p95_ms": round(stats.percentile(95), 2),
                "count": stats.count,
                "error_rate": round(stats.error_rate, 4),
            })
        stages.sort(key=lambda s: s["avg_ms"], reverse=True)
        return stages

    def get_recent_errors(self, limit: int = 50) -> list[dict[str, Any]]:
        return self._recent_errors[-limit:]

    def get_health(self) -> dict[str, Any]:
        stage_health = {}
        for name, stats in self._stages.items():
            stage_health[name] = stats.health

        overall = "healthy"
        healths = list(stage_health.values())
        if any(h == "failed" for h in healths):
            overall = "failed"
        elif any(h == "degraded" for h in healths):
            overall = "degraded"

        return {
            "status": overall,
            "stages": stage_health,
            "events_processed": self._pipeline_count,
            "events_per_minute": self.get_overall_metrics()["events_per_minute"],
        }

    # ------------------------------------------------------------------
    # Redis push (best-effort)
    # ------------------------------------------------------------------

    def _try_push_redis(self, stage: str, duration_ms: float, status: str) -> None:
        try:
            from apps.api.cache import get_redis_client
            r = get_redis_client()
            if r is None:
                return
            key = f"pipeline:metrics:{stage}"
            r.hincrby(key, "count", 1)
            r.hincrby(key, status, 1)
            r.hincrbyfloat(key, "total_ms", duration_ms)
            r.expire(key, 7200)
            # Overall counter
            r.hincrby("pipeline:metrics:_overall", "count", 1)
            r.expire("pipeline:metrics:_overall", 7200)
        except Exception:
            logger.debug("metrics: ignored exception", exc_info=True)


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_metrics_instance: PipelineMetrics | None = None


def get_pipeline_metrics() -> PipelineMetrics:
    global _metrics_instance
    if _metrics_instance is None:
        _metrics_instance = PipelineMetrics()
    return _metrics_instance
