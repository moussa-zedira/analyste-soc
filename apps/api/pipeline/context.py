"""Pipeline Event Context — carries data through all pipeline stages."""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any


@dataclass
class StageMetadata:
    """Execution metadata for a single stage."""

    name: str
    started_at: datetime | None = None
    finished_at: datetime | None = None
    duration_ms: float = 0.0
    status: str = "pending"  # pending | running | success | skipped | error
    error: str | None = None


@dataclass
class EventContext:
    """Accumulates enrichment data as an event flows through the pipeline.

    Created at INGEST, enriched at each subsequent stage, and finally
    persisted at STORE.
    """

    # --- Raw input ---
    raw: Any = None

    # --- Parsed / normalised event fields ---
    parsed: dict[str, Any] = field(default_factory=dict)

    # --- Enrichment results keyed by stage name ---
    enrichments: dict[str, Any] = field(default_factory=dict)

    # --- Detection results ---
    detections: list[dict[str, Any]] = field(default_factory=list)

    # --- Correlation results ---
    correlations: list[dict[str, Any]] = field(default_factory=list)

    # --- IOC match results ---
    ioc_matches: list[dict[str, Any]] = field(default_factory=list)

    # --- Incidents created during pipeline ---
    incidents: list[dict[str, Any]] = field(default_factory=list)

    # --- SOAR playbook executions ---
    soar_executions: list[dict[str, Any]] = field(default_factory=list)

    # --- Alerts dispatched ---
    alerts_sent: list[dict[str, Any]] = field(default_factory=list)

    # --- Composite threat score ---
    score: int = 0

    # --- Pipeline execution metadata ---
    metadata: dict[str, Any] = field(default_factory=dict)

    # --- Per-stage timing ---
    stage_meta: list[StageMetadata] = field(default_factory=list)

    # --- Internal context id ---
    context_id: str = field(default_factory=lambda: str(uuid.uuid4()))

    # --- Dry-run flag ---
    dry_run: bool = False

    # ------------------------------------------------------------------
    # Convenience helpers
    # ------------------------------------------------------------------

    def add_enrichment(self, key: str, data: Any) -> None:
        """Attach enrichment data under *key*."""
        self.enrichments[key] = data

    def add_detection(self, detection: dict[str, Any]) -> None:
        """Record a detection / alert triggered by this event."""
        self.detections.append(detection)

    def add_correlation(self, match: dict[str, Any]) -> None:
        self.correlations.append(match)

    def add_ioc_match(self, match: dict[str, Any]) -> None:
        self.ioc_matches.append(match)

    def add_incident(self, incident: dict[str, Any]) -> None:
        self.incidents.append(incident)

    def add_soar_execution(self, execution: dict[str, Any]) -> None:
        self.soar_executions.append(execution)

    def add_alert(self, alert: dict[str, Any]) -> None:
        self.alerts_sent.append(alert)

    # ------------------------------------------------------------------
    # Conversion
    # ------------------------------------------------------------------

    def to_event_dict(self) -> dict[str, Any]:
        """Return a dict suitable for creating an Event model instance."""
        base = dict(self.parsed)
        if not base.get("id"):
            base["id"] = self.context_id
        if not base.get("ts"):
            base["ts"] = datetime.now(timezone.utc)
        # Merge TI score
        ti = self.enrichments.get("ti", {})
        if ti:
            base["ti_score"] = ti.get("risk_score", self.score)
            tags = ti.get("tags", [])
            if tags:
                import json
                base["ti_tags"] = json.dumps(tags[:20])
        if self.score and not base.get("ti_score"):
            base["ti_score"] = self.score
        return base

    def to_dict(self) -> dict[str, Any]:
        """Full serialisation of the context for API responses / logging."""
        return {
            "context_id": self.context_id,
            "parsed": self.parsed,
            "enrichments": self.enrichments,
            "detections": self.detections,
            "correlations": self.correlations,
            "ioc_matches": self.ioc_matches,
            "incidents": self.incidents,
            "soar_executions": self.soar_executions,
            "alerts_sent": self.alerts_sent,
            "score": self.score,
            "dry_run": self.dry_run,
            "stages": [
                {
                    "name": sm.name,
                    "status": sm.status,
                    "duration_ms": sm.duration_ms,
                    "error": sm.error,
                }
                for sm in self.stage_meta
            ],
        }
