"""Event Pipeline Engine — automated event processing from ingestion to storage.

Chains together parsing, enrichment, detection, correlation, SOAR, and alerting
into a single zero-touch pipeline.
"""

from __future__ import annotations

from apps.api.pipeline.engine import PipelineEngine, PipelineMode
from apps.api.pipeline.context import EventContext
from apps.api.pipeline.config import PipelineConfig, get_pipeline_config

__all__ = [
    "PipelineEngine",
    "PipelineMode",
    "EventContext",
    "PipelineConfig",
    "get_pipeline_config",
]
