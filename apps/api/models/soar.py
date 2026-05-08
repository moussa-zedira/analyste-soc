"""SQLAlchemy models for the SOAR engine — playbooks, executions, steps."""

from __future__ import annotations

from datetime import datetime

from sqlalchemy import JSON, Boolean, DateTime, Float, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column

from apps.api.db.base import Base


class Playbook(Base):
    """Playbook SOAR — definition YAML stockee en base."""

    __tablename__ = "soar_playbooks"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    name: Mapped[str] = mapped_column(Text, index=True)
    description: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str] = mapped_column(Text, index=True, default="custom")
    trigger_type: Mapped[str] = mapped_column(Text, default="manual")
    trigger_config: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    definition: Mapped[dict] = mapped_column(JSON)
    enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    builtin: Mapped[bool] = mapped_column(Boolean, default=False)
    version: Mapped[int] = mapped_column(Integer, default=1)
    tags: Mapped[list | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(Text, default="system")


class PlaybookExecution(Base):
    """Execution d'un playbook — trace d'audit complete."""

    __tablename__ = "soar_executions"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    playbook_id: Mapped[str] = mapped_column(Text, index=True)
    playbook_name: Mapped[str] = mapped_column(Text, default="")
    status: Mapped[str] = mapped_column(Text, index=True, default="pending")
    trigger: Mapped[str] = mapped_column(Text, default="manual")
    input_data: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    variables: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    result: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    dry_run: Mapped[bool] = mapped_column(Boolean, default=False)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_by: Mapped[str] = mapped_column(Text, default="system")
    celery_task_id: Mapped[str | None] = mapped_column(Text, nullable=True)
    incident_id: Mapped[str | None] = mapped_column(Text, nullable=True)


class PlaybookStepResult(Base):
    """Resultat d'une etape individuelle dans une execution."""

    __tablename__ = "soar_step_results"

    id: Mapped[str] = mapped_column(Text, primary_key=True)
    execution_id: Mapped[str] = mapped_column(Text, index=True)
    step_name: Mapped[str] = mapped_column(Text)
    step_index: Mapped[int] = mapped_column(Integer)
    action: Mapped[str] = mapped_column(Text)
    status: Mapped[str] = mapped_column(Text, default="pending")
    input_params: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    output: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    finished_at: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True,
    )
    duration_ms: Mapped[float | None] = mapped_column(Float, nullable=True)
    skipped: Mapped[bool] = mapped_column(Boolean, default=False)
    skip_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
