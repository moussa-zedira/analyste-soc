"""SQLAlchemy models for the DevSecOps CI/CD scanner system."""

from __future__ import annotations

from sqlalchemy import (
    JSON,
    Boolean,
    Column,
    DateTime,
    ForeignKey,
    Integer,
    String,
    Text,
    func,
)

from apps.api.db.base import Base


class ScanProject(Base):
    """A project configured for DevSecOps scanning."""

    __tablename__ = "devsecops_projects"

    id = Column(Integer, primary_key=True, autoincrement=True)
    name = Column(String(255), nullable=False, index=True)
    repo_url = Column(String(1024), nullable=True)
    branch = Column(String(255), default="main")
    language = Column(String(64), nullable=True)
    description = Column(Text, nullable=True)
    config = Column(JSON, nullable=True)
    last_scan_at = Column(DateTime, nullable=True)
    created_at = Column(DateTime, server_default=func.now())
    updated_at = Column(DateTime, onupdate=func.now())


class ScanRun(Base):
    """A single scan execution against a project."""

    __tablename__ = "devsecops_runs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("devsecops_projects.id"), nullable=True, index=True)
    scan_type = Column(
        String(32), nullable=False, index=True
    )  # sast, sca, secrets, dast, container, iac, full
    status = Column(String(20), default="pending")  # pending, running, completed, failed
    started_at = Column(DateTime, nullable=True)
    finished_at = Column(DateTime, nullable=True)
    findings_count = Column(Integer, default=0)
    critical_count = Column(Integer, default=0)
    high_count = Column(Integer, default=0)
    medium_count = Column(Integer, default=0)
    low_count = Column(Integer, default=0)
    quality_gate_passed = Column(Boolean, nullable=True)
    trigger = Column(String(64), default="manual")  # manual, webhook, ci
    meta = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class ScanFinding(Base):
    """An individual security finding from a scan run."""

    __tablename__ = "devsecops_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    run_id = Column(Integer, ForeignKey("devsecops_runs.id"), nullable=False, index=True)
    scan_type = Column(String(32), nullable=False, index=True)
    severity = Column(String(16), nullable=False, index=True)  # critical, high, medium, low, info
    cwe_id = Column(String(32), nullable=True)
    title = Column(String(512), nullable=False)
    description = Column(Text, nullable=True)
    file_path = Column(String(1024), nullable=True)
    line_number = Column(Integer, nullable=True)
    code_snippet = Column(Text, nullable=True)
    remediation = Column(Text, nullable=True)
    false_positive = Column(Boolean, default=False)
    resolved = Column(Boolean, default=False)
    raw_data = Column(JSON, nullable=True)
    created_at = Column(DateTime, server_default=func.now())


class QualityGate(Base):
    """Quality gate definition for pass/fail criteria."""

    __tablename__ = "devsecops_quality_gates"

    id = Column(Integer, primary_key=True, autoincrement=True)
    project_id = Column(Integer, ForeignKey("devsecops_projects.id"), nullable=True, index=True)
    name = Column(String(255), nullable=False)
    max_critical = Column(Integer, default=0)
    max_high = Column(Integer, default=5)
    max_medium = Column(Integer, nullable=True)
    no_secrets = Column(Boolean, default=True)
    custom_rules = Column(JSON, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, server_default=func.now())
