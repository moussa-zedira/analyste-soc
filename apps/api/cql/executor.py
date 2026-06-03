"""CQL Executor — translates parsed CQL into SQLAlchemy queries and runs pipe commands."""

from __future__ import annotations

import re
import time
from datetime import UTC, datetime, timedelta
from typing import Any

from sqlalchemy import and_, not_ as sa_not, or_
from sqlalchemy.orm import Session

from apps.api.cql.commands import execute_command
from apps.api.cql.lexer import LexerError
from apps.api.cql.parser import (
    ASTNode,
    BoolOp,
    Comparison,
    Literal,
    NotExpr,
    ParseError,
    Parser,
    ValueList,
)
from apps.api.models.event import Event

# ---------------------------------------------------------------------------
# Field alias mapping
# ---------------------------------------------------------------------------

FIELD_ALIASES: dict[str, str] = {
    "ip": "src_ip",
    "source_ip": "src_ip",
    "dest_ip": "dst_ip",
    "destination_ip": "dst_ip",
    "dest": "dst_ip",
    "user": "username",
    "login": "username",
    "type": "event_type",
    "time": "ts",
    "timestamp": "ts",
    "score": "ti_score",
    "threat_score": "ti_score",
    "tags": "ti_tags",
    "msg": "message",
    "log": "message",
    "body": "raw",
}

# All valid event fields for validation
EVENT_FIELDS: dict[str, dict[str, str]] = {
    "id": {"type": "string", "description": "Unique event identifier (UUID)"},
    "ts": {"type": "datetime", "description": "Event timestamp (UTC)"},
    "source": {"type": "string", "description": "Log source name"},
    "event_type": {"type": "string", "description": "Event type classification"},
    "severity": {"type": "string", "description": "Severity level: low, medium, high"},
    "src_ip": {"type": "string", "description": "Source IP address"},
    "dst_ip": {"type": "string", "description": "Destination IP address"},
    "username": {"type": "string", "description": "Username associated with event"},
    "message": {"type": "string", "description": "Human-readable event message"},
    "raw": {"type": "string", "description": "Raw log data (JSON or text)"},
    "ti_score": {"type": "integer", "description": "Threat intelligence score (0-100)"},
    "ti_tags": {"type": "string", "description": "Threat intelligence tags (comma-separated)"},
}

# Field type info for operator validation
_STRING_FIELDS = {
    "id",
    "source",
    "event_type",
    "severity",
    "src_ip",
    "dst_ip",
    "username",
    "message",
    "raw",
    "ti_tags",
}
_NUMERIC_FIELDS = {"ti_score"}
_DATETIME_FIELDS = {"ts"}

# Maximum query execution time in seconds
MAX_QUERY_TIME = 30.0
# Maximum rows fetched from DB before pipe processing
MAX_DB_ROWS = 50_000


def _resolve_field(name: str) -> str:
    """Resolve a field name through aliases."""
    return FIELD_ALIASES.get(name.lower(), name)


def _get_column(field_name: str):
    """Get the SQLAlchemy column for a field name."""
    resolved = _resolve_field(field_name)
    col = getattr(Event, resolved, None)
    if col is None:
        raise ParseError(f"Unknown field: {field_name}")
    return col


def _parse_relative_time(s: str) -> datetime:
    """Parse relative time like '-24h', '-7d', '-30m', 'now'."""
    if s.lower() == "now":
        return datetime.now(UTC)

    m = re.match(r"^-(\d+)(s|m|h|d|w)$", s.strip())
    if m:
        val, unit = int(m.group(1)), m.group(2)
        mapping = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
        delta = timedelta(**{mapping[unit]: val})
        return datetime.now(UTC) - delta

    # Try ISO format
    try:
        return datetime.fromisoformat(s)
    except (ValueError, TypeError):
        raise ParseError(f"Invalid time expression: {s}")


# ---------------------------------------------------------------------------
# AST to SQLAlchemy WHERE clause
# ---------------------------------------------------------------------------


def _ast_to_filter(node: ASTNode):
    """Convert an AST filter expression to a SQLAlchemy filter clause."""
    if isinstance(node, Comparison):
        return _comparison_to_filter(node)
    if isinstance(node, BoolOp):
        left = _ast_to_filter(node.left) if node.left else None
        right = _ast_to_filter(node.right) if node.right else None
        if left is None:
            return right
        if right is None:
            return left
        if node.op == "AND":
            return and_(left, right)
        return or_(left, right)
    if isinstance(node, NotExpr):
        if node.operand:
            return sa_not(_ast_to_filter(node.operand))
        return None
    raise ParseError(f"Unexpected AST node type: {type(node).__name__}")


def _comparison_to_filter(node: Comparison):
    """Convert a single comparison to SQLAlchemy filter."""
    col = _get_column(node.field.name)
    op = node.operator

    if isinstance(node.value, ValueList):
        values = [lit.value for lit in node.value.values]
        if op == "IN":
            return col.in_(values)
        if op == "NOT IN":
            return ~col.in_(values)

    if isinstance(node.value, Literal):
        val = node.value.value
    else:
        raise ParseError(f"Unexpected value node: {type(node.value).__name__}")

    if op == "=":
        # Handle wildcards
        if isinstance(val, str) and ("*" in val or "?" in val):
            pattern = val.replace("*", "%").replace("?", "_")
            return col.like(pattern)
        return col == val
    if op == "!=":
        return col != val
    if op == ">":
        return col > val
    if op == ">=":
        return col >= val
    if op == "<":
        return col < val
    if op == "<=":
        return col <= val
    if op == "LIKE":
        pattern = str(val).replace("*", "%").replace("?", "_")
        return col.like(pattern)
    if op == "CONTAINS":
        return col.contains(str(val))
    if op == "STARTSWITH":
        return col.startswith(str(val))
    if op == "ENDSWITH":
        return col.endswith(str(val))
    if op == "MATCHES":
        # For SQLite, use LIKE as a fallback; for PostgreSQL use ~ operator
        # Using LIKE with wildcards as portable approach
        return col.op("REGEXP")(str(val))

    raise ParseError(f"Unknown operator: {op}")


# ---------------------------------------------------------------------------
# Event row to dict
# ---------------------------------------------------------------------------


def _event_to_dict(event: Event) -> dict[str, Any]:
    return {
        "id": event.id,
        "ts": event.ts.isoformat() if event.ts else None,
        "source": event.source,
        "event_type": event.event_type,
        "severity": event.severity,
        "src_ip": event.src_ip,
        "dst_ip": event.dst_ip,
        "username": event.username,
        "message": event.message,
        "raw": event.raw,
        "ti_score": event.ti_score,
        "ti_tags": event.ti_tags,
    }


# ---------------------------------------------------------------------------
# Main executor
# ---------------------------------------------------------------------------


def execute_cql(
    query_str: str,
    db: Session,
    *,
    limit: int = 1000,
    offset: int = 0,
    default_earliest: str = "-24h",
    default_latest: str = "now",
) -> dict[str, Any]:
    """Execute a CQL query and return results with metadata.

    Returns::

        {
            "results": [...],
            "metadata": {
                "total": int,
                "returned": int,
                "execution_time_ms": float,
                "query": str,
                "commands": [...],
            },
        }
    """
    start_time = time.time()

    try:
        parser = Parser.from_query(query_str)
        ast = parser.parse()
    except (LexerError, ParseError) as exc:
        return {
            "results": [],
            "metadata": {
                "total": 0,
                "returned": 0,
                "execution_time_ms": round((time.time() - start_time) * 1000, 2),
                "query": query_str,
                "error": str(exc),
            },
        }

    # Build SQLAlchemy query
    q = db.query(Event)

    # Apply time range
    earliest = ast.earliest or default_earliest
    latest = ast.latest or default_latest

    try:
        earliest_dt = _parse_relative_time(earliest)
        latest_dt = _parse_relative_time(latest)
        q = q.filter(Event.ts >= earliest_dt, Event.ts <= latest_dt)
    except ParseError:
        pass  # Skip time filter if parsing fails

    # Apply filter expression
    if ast.filter_expr:
        try:
            where_clause = _ast_to_filter(ast.filter_expr)
            if where_clause is not None:
                q = q.filter(where_clause)
        except ParseError as exc:
            return {
                "results": [],
                "metadata": {
                    "total": 0,
                    "returned": 0,
                    "execution_time_ms": round((time.time() - start_time) * 1000, 2),
                    "query": query_str,
                    "error": str(exc),
                },
            }

    # Check if we can push aggregation to DB level
    has_stats = any(cmd.name == "stats" for cmd in ast.commands)
    has_sort = any(cmd.name == "sort" for cmd in ast.commands)

    # Order by ts desc by default
    if not has_sort and not has_stats:
        q = q.order_by(Event.ts.desc())

    # Fetch from DB
    db_limit = MAX_DB_ROWS if has_stats else min(limit + offset + 1000, MAX_DB_ROWS)
    events = q.limit(db_limit).all()

    # Check execution time
    elapsed = time.time() - start_time
    if elapsed > MAX_QUERY_TIME:
        return {
            "results": [],
            "metadata": {
                "total": 0,
                "returned": 0,
                "execution_time_ms": round(elapsed * 1000, 2),
                "query": query_str,
                "error": f"Query timeout: exceeded {MAX_QUERY_TIME}s",
            },
        }

    # Convert to dicts
    rows = [_event_to_dict(e) for e in events]
    len(rows)

    # Apply pipe commands
    command_names = []
    for cmd in ast.commands:
        command_names.append(cmd.name)
        try:
            rows = execute_command(cmd.name, rows, cmd.args, cmd.raw_text)
        except ValueError as exc:
            return {
                "results": [],
                "metadata": {
                    "total": 0,
                    "returned": 0,
                    "execution_time_ms": round((time.time() - start_time) * 1000, 2),
                    "query": query_str,
                    "error": str(exc),
                },
            }

        # Check timeout after each command
        if time.time() - start_time > MAX_QUERY_TIME:
            return {
                "results": rows[:limit],
                "metadata": {
                    "total": len(rows),
                    "returned": min(len(rows), limit),
                    "execution_time_ms": round((time.time() - start_time) * 1000, 2),
                    "query": query_str,
                    "error": f"Query timeout during command '{cmd.name}'",
                },
            }

    # Apply pagination (only if no stats/aggregation commands were used)
    total = len(rows)
    if not has_stats:
        rows = rows[offset : offset + limit]

    elapsed_ms = round((time.time() - start_time) * 1000, 2)

    return {
        "results": rows,
        "metadata": {
            "total": total,
            "returned": len(rows),
            "execution_time_ms": elapsed_ms,
            "query": query_str,
            "commands": command_names,
            "earliest": earliest,
            "latest": latest,
        },
    }


def explain_cql(query_str: str) -> dict[str, Any]:
    """Explain query plan without executing.

    Returns the parsed AST structure, filter fields, commands, and optimization hints.
    """
    try:
        parser = Parser.from_query(query_str)
        ast = parser.parse()
    except (LexerError, ParseError) as exc:
        return {"error": str(exc), "valid": False}

    # Extract filter fields
    filter_fields: list[str] = []
    _extract_fields(ast.filter_expr, filter_fields)

    # Check which indexes would be used
    indexed_fields = {"ts", "event_type", "src_ip"}
    used_indexes = [f for f in filter_fields if _resolve_field(f) in indexed_fields]
    unindexed_fields = [f for f in filter_fields if _resolve_field(f) not in indexed_fields]

    # Optimization hints
    hints: list[str] = []
    if not ast.earliest and not ast.latest:
        hints.append(
            "No time range specified; defaults to last 24h. Add 'earliest=-7d' for wider range."
        )
    if unindexed_fields:
        hints.append(f"Fields without index: {', '.join(unindexed_fields)}. Query may be slower.")
    if any(cmd.name == "stats" for cmd in ast.commands):
        hints.append("Stats command will aggregate results in memory after DB fetch.")

    commands = [{"name": cmd.name, "args": cmd.raw_text} for cmd in ast.commands]

    return {
        "valid": True,
        "filter_fields": filter_fields,
        "used_indexes": used_indexes,
        "unindexed_fields": unindexed_fields,
        "commands": commands,
        "earliest": ast.earliest or "-24h (default)",
        "latest": ast.latest or "now (default)",
        "hints": hints,
    }


def _extract_fields(node: ASTNode | None, fields: list[str]) -> None:
    """Extract all field names referenced in a filter expression."""
    if node is None:
        return
    if isinstance(node, Comparison):
        fields.append(node.field.name)
    elif isinstance(node, BoolOp):
        _extract_fields(node.left, fields)
        _extract_fields(node.right, fields)
    elif isinstance(node, NotExpr):
        _extract_fields(node.operand, fields)
