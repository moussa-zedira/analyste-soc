"""Pipeline configuration — stage ordering, timeouts, modes."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class StageConfig:
    """Per-stage configuration."""

    enabled: bool = True
    timeout_seconds: float = 30.0


# Ordered list of stage names matching the classes in stages.py
STAGE_ORDER: list[str] = [
    "ingest",
    "parse",
    "enrich_geo",
    "enrich_ti",
    "enrich_asset",
    "classify",
    "score",
    "detect",
    "correlate",
    "ioc_match",
    "soar_trigger",
    "alert",
    "store",
]

# Default timeouts per stage
_DEFAULT_TIMEOUTS: dict[str, float] = {
    "ingest": 5.0,
    "parse": 5.0,
    "enrich_geo": 10.0,
    "enrich_ti": 30.0,
    "enrich_asset": 10.0,
    "classify": 10.0,
    "score": 5.0,
    "detect": 30.0,
    "correlate": 30.0,
    "ioc_match": 15.0,
    "soar_trigger": 60.0,
    "alert": 30.0,
    "store": 10.0,
}


@dataclass
class PipelineConfig:
    """Full pipeline configuration."""

    # Per-stage overrides
    stages: dict[str, StageConfig] = field(default_factory=dict)

    # Batch mode settings
    batch_size: int = 100

    # Realtime mode concurrency
    max_concurrent_events: int = 50

    # Whether to use ML classification (fallback to rule-based if False)
    ml_classification_enabled: bool = False

    # TI providers to use (empty = all configured)
    ti_providers: list[str] = field(default_factory=list)

    # Alert channel selection per severity (severity -> [channel_type])
    alert_channels: dict[str, list[str]] = field(default_factory=dict)

    # Continue processing on stage failure
    continue_on_error: bool = True

    # Parallel enrichment stages (geo + ti + asset can run concurrently)
    parallel_enrichment: bool = True

    def __post_init__(self) -> None:
        # Fill in defaults for missing stages
        for name in STAGE_ORDER:
            if name not in self.stages:
                self.stages[name] = StageConfig(
                    timeout_seconds=_DEFAULT_TIMEOUTS.get(name, 30.0),
                )

    def is_stage_enabled(self, name: str) -> bool:
        cfg = self.stages.get(name)
        return cfg.enabled if cfg else True

    def get_timeout(self, name: str) -> float:
        cfg = self.stages.get(name)
        return cfg.timeout_seconds if cfg else 30.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "stages": {
                name: {"enabled": sc.enabled, "timeout_seconds": sc.timeout_seconds}
                for name, sc in self.stages.items()
            },
            "batch_size": self.batch_size,
            "max_concurrent_events": self.max_concurrent_events,
            "ml_classification_enabled": self.ml_classification_enabled,
            "ti_providers": self.ti_providers,
            "alert_channels": self.alert_channels,
            "continue_on_error": self.continue_on_error,
            "parallel_enrichment": self.parallel_enrichment,
        }


# ---------------------------------------------------------------------------
# Singleton
# ---------------------------------------------------------------------------

_config_instance: PipelineConfig | None = None


def get_pipeline_config() -> PipelineConfig:
    global _config_instance
    if _config_instance is None:
        _config_instance = PipelineConfig()
    return _config_instance


def update_pipeline_config(updates: dict[str, Any]) -> PipelineConfig:
    """Apply partial updates to the pipeline config and return it."""
    cfg = get_pipeline_config()

    if "batch_size" in updates:
        cfg.batch_size = int(updates["batch_size"])
    if "max_concurrent_events" in updates:
        cfg.max_concurrent_events = int(updates["max_concurrent_events"])
    if "ml_classification_enabled" in updates:
        cfg.ml_classification_enabled = bool(updates["ml_classification_enabled"])
    if "ti_providers" in updates:
        cfg.ti_providers = list(updates["ti_providers"])
    if "alert_channels" in updates:
        cfg.alert_channels = dict(updates["alert_channels"])
    if "continue_on_error" in updates:
        cfg.continue_on_error = bool(updates["continue_on_error"])
    if "parallel_enrichment" in updates:
        cfg.parallel_enrichment = bool(updates["parallel_enrichment"])

    # Stage-level updates: {"stages": {"enrich_ti": {"enabled": false}}}
    if "stages" in updates and isinstance(updates["stages"], dict):
        for name, overrides in updates["stages"].items():
            if name not in cfg.stages:
                cfg.stages[name] = StageConfig()
            if "enabled" in overrides:
                cfg.stages[name].enabled = bool(overrides["enabled"])
            if "timeout_seconds" in overrides:
                cfg.stages[name].timeout_seconds = float(overrides["timeout_seconds"])

    return cfg
