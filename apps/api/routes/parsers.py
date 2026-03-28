"""API endpoints for log parsing and normalization.

Endpoints:
    POST /api/parsers/detect   — auto-detect log format from sample
    POST /api/parsers/parse    — parse raw log line(s)
    GET  /api/parsers/formats  — list all supported formats
    POST /api/parsers/test     — test a parser against sample data
    POST /api/ingest/bulk      — bulk ingest with auto-parsing
"""

from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, Field

from apps.api.parsers import (
    detect,
    detect_format,
    parse_line,
    parse_bulk,
    supported_formats,
    get_registry,
)

router = APIRouter()


# ---------------------------------------------------------------------------
# Request / Response models
# ---------------------------------------------------------------------------

class DetectRequest(BaseModel):
    raw: str = Field(..., description="Raw log line or block to analyse")


class DetectResponse(BaseModel):
    format: str | None = Field(None, description="Detected format name")
    parser: str | None = Field(None, description="Parser that matched")
    confidence: str = Field("high", description="Detection confidence (high/medium/low)")


class ParseRequest(BaseModel):
    raw: str | list[str] = Field(
        ..., description="Raw log line(s) — string or list of strings"
    )
    parser: str | None = Field(
        None, description="Force a specific parser by name (skip auto-detect)"
    )


class ParsedEvent(BaseModel):
    id: str
    ts: str
    source: str
    event_type: str
    severity: str
    src_ip: str | None = None
    dst_ip: str | None = None
    username: str | None = None
    message: str | None = None
    raw: str | None = None


class ParseResponse(BaseModel):
    parsed: list[ParsedEvent]
    total: int
    failed: int


class TestRequest(BaseModel):
    parser: str = Field(..., description="Parser name to test")
    samples: list[str] = Field(..., description="List of sample log lines")


class TestResult(BaseModel):
    line: str
    matched: bool
    parsed: dict[str, Any] | None = None
    error: str | None = None


class TestResponse(BaseModel):
    parser: str
    total: int
    matched: int
    failed: int
    results: list[TestResult]


class BulkIngestRequest(BaseModel):
    lines: list[str] = Field(..., description="Raw log lines to ingest")
    source_tag: str | None = Field(None, description="Override source tag")
    store: bool = Field(False, description="Persist to database")


class BulkIngestResponse(BaseModel):
    ingested: int
    failed: int
    events: list[ParsedEvent]


class FormatInfo(BaseModel):
    name: str
    formats: list[str]
    priority: int


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _to_parsed_event(ev: dict[str, Any]) -> ParsedEvent:
    ts = ev.get("ts")
    if isinstance(ts, datetime):
        ts_str = ts.isoformat()
    else:
        ts_str = str(ts) if ts else datetime.now(timezone.utc).isoformat()

    return ParsedEvent(
        id=ev.get("id") or str(uuid.uuid4()),
        ts=ts_str,
        source=ev.get("source", "unknown"),
        event_type=ev.get("event_type", "unknown"),
        severity=ev.get("severity", "low"),
        src_ip=ev.get("src_ip"),
        dst_ip=ev.get("dst_ip"),
        username=ev.get("username"),
        message=ev.get("message"),
        raw=ev.get("raw"),
    )


def _find_parser(name: str):
    for p in get_registry():
        if p.name == name:
            return p
    return None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------

@router.post("/detect", response_model=DetectResponse, summary="Auto-detect log format")
def api_detect(req: DetectRequest):
    """Analyse a raw log line and return the detected format."""
    parser = detect(req.raw)
    if parser is None:
        return DetectResponse(format=None, parser=None, confidence="low")
    return DetectResponse(
        format=parser.formats[0] if parser.formats else parser.name,
        parser=parser.name,
        confidence="high",
    )


@router.post("/parse", response_model=ParseResponse, summary="Parse raw log line(s)")
def api_parse(req: ParseRequest):
    """Parse one or more raw log lines into normalised Event dicts."""
    lines = [req.raw] if isinstance(req.raw, str) else req.raw

    parsed_events: list[ParsedEvent] = []
    failed = 0

    for line in lines:
        line = line.strip()
        if not line:
            continue
        if req.parser:
            p = _find_parser(req.parser)
            if p is None:
                raise HTTPException(404, detail=f"Parser '{req.parser}' not found")
            if p.can_parse(line):
                result = p.parse(line)
                if result is not None:
                    norm = p.normalize(result, raw=line)
                    parsed_events.append(_to_parsed_event(norm))
                    continue
            failed += 1
        else:
            result = parse_line(line)
            if result is not None:
                parsed_events.append(_to_parsed_event(result))
            else:
                failed += 1

    return ParseResponse(
        parsed=parsed_events,
        total=len(parsed_events) + failed,
        failed=failed,
    )


@router.get("/formats", response_model=list[FormatInfo], summary="List supported formats")
def api_formats():
    """Return metadata about every registered parser."""
    return [
        FormatInfo(name=f["name"], formats=f["formats"], priority=f["priority"])
        for f in supported_formats()
    ]


@router.post("/test", response_model=TestResponse, summary="Test parser against samples")
def api_test(req: TestRequest):
    """Test a specific parser against a list of sample log lines."""
    p = _find_parser(req.parser)
    if p is None:
        raise HTTPException(404, detail=f"Parser '{req.parser}' not found")

    results: list[TestResult] = []
    matched = 0
    failed = 0

    for sample in req.samples:
        sample = sample.strip()
        if not sample:
            continue
        try:
            if p.can_parse(sample):
                parsed = p.parse(sample)
                if parsed is not None:
                    norm = p.normalize(parsed, raw=sample)
                    # Strip internal fields for display
                    clean = {k: v for k, v in norm.items() if not k.startswith("_")}
                    if isinstance(clean.get("ts"), datetime):
                        clean["ts"] = clean["ts"].isoformat()
                    results.append(TestResult(line=sample, matched=True, parsed=clean))
                    matched += 1
                else:
                    results.append(TestResult(line=sample, matched=False, error="Parser returned None"))
                    failed += 1
            else:
                results.append(TestResult(line=sample, matched=False, error="can_parse returned False"))
                failed += 1
        except Exception as exc:
            results.append(TestResult(line=sample, matched=False, error=str(exc)))
            failed += 1

    return TestResponse(
        parser=req.parser,
        total=len(results),
        matched=matched,
        failed=failed,
        results=results,
    )


@router.post("/ingest/bulk", response_model=BulkIngestResponse, summary="Bulk ingest with auto-parsing")
def api_bulk_ingest(req: BulkIngestRequest):
    """Parse and optionally store multiple log lines at once."""
    parsed_events: list[ParsedEvent] = []
    failed = 0

    for line in req.lines:
        line = line.strip()
        if not line:
            continue
        result = parse_line(line)
        if result is not None:
            if req.source_tag:
                result["source"] = req.source_tag
            parsed_events.append(_to_parsed_event(result))
        else:
            failed += 1

    # Optionally persist to database
    if req.store and parsed_events:
        try:
            _store_events(parsed_events)
        except Exception:
            pass  # Non-blocking — return parsed data even if DB fails

    return BulkIngestResponse(
        ingested=len(parsed_events),
        failed=failed,
        events=parsed_events,
    )


def _store_events(events: list[ParsedEvent]) -> None:
    """Persist parsed events to the database."""
    from apps.api.db.session import SessionLocal
    from apps.api.models.event import Event

    db = SessionLocal()
    try:
        for ev in events:
            db_event = Event(
                id=ev.id,
                ts=datetime.fromisoformat(ev.ts),
                source=ev.source,
                event_type=ev.event_type,
                severity=ev.severity,
                src_ip=ev.src_ip,
                dst_ip=ev.dst_ip,
                username=ev.username,
                message=ev.message,
                raw=ev.raw,
            )
            db.add(db_event)
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()
