"""CQL Autocomplete Engine — context-aware suggestions for CQL queries."""

from __future__ import annotations

import re
from difflib import SequenceMatcher
from typing import Any

from sqlalchemy.orm import Session

from apps.api.cql.executor import EVENT_FIELDS, FIELD_ALIASES, _STRING_FIELDS, _NUMERIC_FIELDS
from apps.api.cql.commands import list_commands

# ---------------------------------------------------------------------------
# Suggestion types
# ---------------------------------------------------------------------------

SUGGESTION_TYPE_FIELD = "field"
SUGGESTION_TYPE_OPERATOR = "operator"
SUGGESTION_TYPE_VALUE = "value"
SUGGESTION_TYPE_COMMAND = "command"
SUGGESTION_TYPE_KEYWORD = "keyword"
SUGGESTION_TYPE_FUNCTION = "function"


# ---------------------------------------------------------------------------
# Eval functions
# ---------------------------------------------------------------------------

_EVAL_FUNCTIONS = {
    "if": {"syntax": "if(condition, true_val, false_val)", "description": "Conditional expression"},
    "len": {"syntax": "len(field)", "description": "String length"},
    "lower": {"syntax": "lower(field)", "description": "Convert to lowercase"},
    "upper": {"syntax": "upper(field)", "description": "Convert to uppercase"},
    "substr": {"syntax": "substr(field, start, length)", "description": "Extract substring"},
    "replace": {"syntax": "replace(field, old, new)", "description": "Replace text"},
    "concat": {"syntax": "concat(val1, val2, ...)", "description": "Concatenate values"},
    "now": {"syntax": "now()", "description": "Current UTC timestamp"},
    "coalesce": {"syntax": "coalesce(field1, field2, default)", "description": "First non-null value"},
    "abs": {"syntax": "abs(field)", "description": "Absolute value"},
    "ceil": {"syntax": "ceil(field)", "description": "Round up"},
    "floor": {"syntax": "floor(field)", "description": "Round down"},
    "round": {"syntax": "round(field, digits)", "description": "Round to N digits"},
    "log": {"syntax": "log(field)", "description": "Natural logarithm"},
    "sqrt": {"syntax": "sqrt(field)", "description": "Square root"},
    "split": {"syntax": "split(field, delimiter)", "description": "Split string into multi-value"},
    "urldecode": {"syntax": "urldecode(field)", "description": "URL decode"},
    "base64decode": {"syntax": "base64decode(field)", "description": "Base64 decode"},
    "md5": {"syntax": "md5(field)", "description": "MD5 hash"},
    "sha256": {"syntax": "sha256(field)", "description": "SHA-256 hash"},
    "cidrmatch": {"syntax": 'cidrmatch("10.0.0.0/8", src_ip)', "description": "CIDR match check"},
}

# Aggregation functions used in stats
_AGG_FUNCTIONS = {
    "count": {"syntax": "count / count(field)", "description": "Count events or non-null values"},
    "sum": {"syntax": "sum(field)", "description": "Sum of numeric field"},
    "avg": {"syntax": "avg(field)", "description": "Average of numeric field"},
    "min": {"syntax": "min(field)", "description": "Minimum value"},
    "max": {"syntax": "max(field)", "description": "Maximum value"},
    "dc": {"syntax": "dc(field)", "description": "Distinct count"},
    "distinct_count": {"syntax": "distinct_count(field)", "description": "Distinct count (alias)"},
    "values": {"syntax": "values(field)", "description": "List of unique values"},
    "first": {"syntax": "first(field)", "description": "First value"},
    "last": {"syntax": "last(field)", "description": "Last value"},
}


# ---------------------------------------------------------------------------
# Context detection
# ---------------------------------------------------------------------------

def _detect_context(query: str, cursor: int) -> dict[str, Any]:
    """Analyze query text up to cursor position to determine suggestion context."""
    before = query[:cursor].rstrip()
    parts = before.split()

    ctx: dict[str, Any] = {
        "context": "filter",  # filter, command, operator, value, by_field, eval_expr, stats_func
        "partial": "",
        "field_name": None,
        "command_name": None,
        "after_pipe": False,
    }

    if not parts:
        ctx["context"] = "filter"
        return ctx

    # Check if we're after a pipe
    pipe_positions = [i for i, ch in enumerate(before) if ch == "|"]
    if pipe_positions:
        after_last_pipe = before[pipe_positions[-1] + 1:].strip()
        ctx["after_pipe"] = True
        pipe_parts = after_last_pipe.split()

        if not pipe_parts:
            ctx["context"] = "command"
            return ctx

        cmd_name = pipe_parts[0].lower()
        ctx["command_name"] = cmd_name

        if len(pipe_parts) == 1 and not before.endswith(" "):
            # Still typing command name
            ctx["context"] = "command"
            ctx["partial"] = cmd_name
            return ctx

        # Context within specific commands
        if cmd_name == "stats":
            last = pipe_parts[-1].lower()
            if last == "by" or (len(pipe_parts) > 1 and pipe_parts[-2].lower() == "by"):
                ctx["context"] = "by_field"
                ctx["partial"] = "" if last == "by" else last.rstrip(",")
            else:
                ctx["context"] = "stats_func"
                ctx["partial"] = last if not before.endswith(" ") else ""
            return ctx

        if cmd_name == "eval":
            ctx["context"] = "eval_expr"
            ctx["partial"] = pipe_parts[-1] if not before.endswith(" ") else ""
            return ctx

        if cmd_name in ("sort", "unique", "dedup", "fields", "table", "top", "rare",
                        "bucket", "iplocation", "mitre", "mvexpand", "trendline",
                        "fillnull", "regex", "timechart"):
            ctx["context"] = "by_field"
            ctx["partial"] = pipe_parts[-1] if not before.endswith(" ") else ""
            return ctx

        if cmd_name == "where":
            # Treat like filter context
            where_parts = pipe_parts[1:]
            if len(where_parts) == 0 or (len(where_parts) == 1 and not before.endswith(" ")):
                ctx["context"] = "filter"
                ctx["partial"] = where_parts[0] if where_parts else ""
                return ctx
            if len(where_parts) == 1 and before.endswith(" "):
                ctx["context"] = "operator"
                ctx["field_name"] = where_parts[0]
                return ctx
            if len(where_parts) >= 2 and before.endswith(" "):
                ctx["context"] = "value"
                ctx["field_name"] = where_parts[0]
                return ctx

        ctx["context"] = "command_args"
        ctx["partial"] = pipe_parts[-1] if not before.endswith(" ") else ""
        return ctx

    # We're in the filter portion
    last = parts[-1]
    second_last = parts[-2] if len(parts) >= 2 else None

    # After a value or closing paren — suggest boolean operator
    if before.endswith(")") or (
        second_last and second_last.upper() in ("=", "!=", ">", ">=", "<", "<=", "LIKE", "CONTAINS", "STARTSWITH", "ENDSWITH", "MATCHES")
    ):
        if before.endswith(" "):
            ctx["context"] = "keyword"
            return ctx

    # After a field name — suggest operator
    if len(parts) >= 1 and not before.endswith(" "):
        ctx["context"] = "filter"
        ctx["partial"] = last
        return ctx

    if len(parts) >= 1 and before.endswith(" "):
        # Check if last token looks like a field name
        if last.upper() not in ("AND", "OR", "NOT", "=", "!=", ">", ">=", "<", "<=",
                                "LIKE", "IN", "CONTAINS", "STARTSWITH", "ENDSWITH", "MATCHES"):
            # Could be field name followed by space -> suggest operators
            if last.lower() in EVENT_FIELDS or last.lower() in FIELD_ALIASES:
                ctx["context"] = "operator"
                ctx["field_name"] = last
                return ctx

        # After an operator -> suggest value
        if last.upper() in ("=", "!=", ">", ">=", "<", "<=", "LIKE", "IN",
                            "CONTAINS", "STARTSWITH", "ENDSWITH", "MATCHES"):
            ctx["context"] = "value"
            ctx["field_name"] = second_last
            return ctx

        # After boolean keyword or value -> suggest field
        ctx["context"] = "filter"
        return ctx

    ctx["partial"] = last if not before.endswith(" ") else ""
    return ctx


# ---------------------------------------------------------------------------
# Fuzzy matching
# ---------------------------------------------------------------------------

def _fuzzy_score(query: str, candidate: str) -> float:
    """Compute fuzzy match score (0-1)."""
    if not query:
        return 0.5
    q_lower = query.lower()
    c_lower = candidate.lower()
    if c_lower.startswith(q_lower):
        return 1.0
    if q_lower in c_lower:
        return 0.8
    return SequenceMatcher(None, q_lower, c_lower).ratio()


# ---------------------------------------------------------------------------
# Suggestion generators
# ---------------------------------------------------------------------------

def _suggest_fields(partial: str) -> list[dict]:
    suggestions = []
    for name, meta in EVENT_FIELDS.items():
        score = _fuzzy_score(partial, name)
        if score > 0.3:
            suggestions.append({
                "text": name,
                "type": SUGGESTION_TYPE_FIELD,
                "description": meta["description"],
                "field_type": meta["type"],
                "score": score,
            })
    # Add aliases
    for alias, target in FIELD_ALIASES.items():
        score = _fuzzy_score(partial, alias)
        if score > 0.3:
            meta = EVENT_FIELDS.get(target, {})
            suggestions.append({
                "text": alias,
                "type": SUGGESTION_TYPE_FIELD,
                "description": f"Alias for {target}: {meta.get('description', '')}",
                "field_type": meta.get("type", "string"),
                "score": score * 0.9,  # Slightly lower for aliases
            })
    return sorted(suggestions, key=lambda s: -s["score"])


def _suggest_operators(field_name: str | None) -> list[dict]:
    resolved = field_name.lower() if field_name else ""
    if resolved in FIELD_ALIASES:
        resolved = FIELD_ALIASES[resolved]

    all_ops = [
        ("=", "Equals"),
        ("!=", "Not equals"),
    ]

    if resolved in _NUMERIC_FIELDS:
        all_ops.extend([
            (">", "Greater than"),
            (">=", "Greater than or equal"),
            ("<", "Less than"),
            ("<=", "Less than or equal"),
            ("IN", "In value list"),
            ("NOT IN", "Not in value list"),
        ])
    elif resolved in _DATETIME_FIELDS:
        all_ops.extend([
            (">", "After"),
            (">=", "At or after"),
            ("<", "Before"),
            ("<=", "At or before"),
        ])
    else:
        all_ops.extend([
            ("LIKE", "Pattern match with wildcards"),
            ("CONTAINS", "Contains substring"),
            ("STARTSWITH", "Starts with"),
            ("ENDSWITH", "Ends with"),
            ("MATCHES", "Regex match"),
            ("IN", "In value list"),
            ("NOT IN", "Not in value list"),
            (">", "Greater than"),
            (">=", "Greater than or equal"),
            ("<", "Less than"),
            ("<=", "Less than or equal"),
        ])

    return [
        {"text": op, "type": SUGGESTION_TYPE_OPERATOR, "description": desc, "score": 1.0 - i * 0.05}
        for i, (op, desc) in enumerate(all_ops)
    ]


def _suggest_values(field_name: str | None, db: Session | None) -> list[dict]:
    """Suggest values for a field. Uses cached recent values when available."""
    if not field_name:
        return []

    resolved = field_name.lower()
    if resolved in FIELD_ALIASES:
        resolved = FIELD_ALIASES[resolved]

    # Static suggestions for known fields
    static: dict[str, list[str]] = {
        "severity": ["low", "medium", "high"],
        "event_type": [
            "auth_failure", "auth_success", "process_create", "privilege_change",
            "rdp_connect", "ssh_connect", "smb_connect", "dns_query",
            "file_create", "file_delete", "file_modify",
            "registry_modify", "scheduled_task", "service_install",
            "network_connection", "firewall_block", "firewall_allow",
            "malware_detected", "ids_alert", "web_request",
        ],
    }

    if resolved in static:
        return [
            {"text": v, "type": SUGGESTION_TYPE_VALUE, "description": f"Value for {resolved}", "score": 0.9}
            for v in static[resolved]
        ]

    # Try to get recent values from Redis cache
    try:
        from apps.api.cache import get_cache, set_cache
        cache_key = f"cql:values:{resolved}"
        cached = get_cache(cache_key)
        if cached:
            return [
                {"text": str(v), "type": SUGGESTION_TYPE_VALUE, "description": "Recent value", "score": 0.8}
                for v in cached[:20]
            ]
    except Exception:
        pass

    # Query DB for recent unique values
    if db is not None:
        try:
            col = getattr(Event, resolved, None)
            if col is not None:
                from sqlalchemy import func as sa_func
                from apps.api.models.event import Event
                vals = (
                    db.query(col)
                    .filter(col.isnot(None))
                    .distinct()
                    .limit(50)
                    .all()
                )
                value_list = [str(v[0]) for v in vals if v[0] is not None]

                # Cache in Redis
                try:
                    from apps.api.cache import set_cache
                    set_cache(f"cql:values:{resolved}", value_list, ttl=300)
                except Exception:
                    pass

                return [
                    {"text": v, "type": SUGGESTION_TYPE_VALUE, "description": "Recent value", "score": 0.8}
                    for v in value_list[:20]
                ]
        except Exception:
            pass

    return []


def _suggest_commands(partial: str) -> list[dict]:
    commands = list_commands()
    suggestions = []
    for name, meta in commands.items():
        score = _fuzzy_score(partial, name)
        if score > 0.3:
            suggestions.append({
                "text": name,
                "type": SUGGESTION_TYPE_COMMAND,
                "description": meta["description"].split("\n")[0] if meta["description"] else "",
                "syntax": meta.get("syntax", ""),
                "score": score,
            })
    return sorted(suggestions, key=lambda s: -s["score"])


def _suggest_keywords() -> list[dict]:
    return [
        {"text": "AND", "type": SUGGESTION_TYPE_KEYWORD, "description": "Boolean AND", "score": 1.0},
        {"text": "OR", "type": SUGGESTION_TYPE_KEYWORD, "description": "Boolean OR", "score": 0.9},
        {"text": "NOT", "type": SUGGESTION_TYPE_KEYWORD, "description": "Boolean NOT", "score": 0.8},
        {"text": "|", "type": SUGGESTION_TYPE_KEYWORD, "description": "Pipe to command", "score": 0.7},
    ]


def _suggest_stats_functions(partial: str) -> list[dict]:
    suggestions = []
    for name, meta in _AGG_FUNCTIONS.items():
        score = _fuzzy_score(partial, name)
        if score > 0.3:
            suggestions.append({
                "text": name,
                "type": SUGGESTION_TYPE_FUNCTION,
                "description": meta["description"],
                "syntax": meta["syntax"],
                "score": score,
            })
    return sorted(suggestions, key=lambda s: -s["score"])


def _suggest_eval_functions(partial: str) -> list[dict]:
    suggestions = []
    for name, meta in _EVAL_FUNCTIONS.items():
        score = _fuzzy_score(partial, name)
        if score > 0.3:
            suggestions.append({
                "text": name,
                "type": SUGGESTION_TYPE_FUNCTION,
                "description": meta["description"],
                "syntax": meta["syntax"],
                "score": score,
            })
    return sorted(suggestions, key=lambda s: -s["score"])


# ---------------------------------------------------------------------------
# Main autocomplete entry point
# ---------------------------------------------------------------------------

def autocomplete_cql(
    query: str,
    cursor_position: int,
    db: Session | None = None,
) -> list[dict]:
    """Return autocomplete suggestions for the given query at cursor position.

    Returns a list of::

        {"text": str, "type": str, "description": str, "score": float}
    """
    ctx = _detect_context(query, cursor_position)
    context = ctx["context"]
    partial = ctx.get("partial", "")

    if context == "filter":
        return _suggest_fields(partial)

    if context == "operator":
        return _suggest_operators(ctx.get("field_name"))

    if context == "value":
        return _suggest_values(ctx.get("field_name"), db)

    if context == "command":
        return _suggest_commands(partial)

    if context == "keyword":
        return _suggest_keywords()

    if context == "by_field":
        return _suggest_fields(partial)

    if context == "stats_func":
        results = _suggest_stats_functions(partial)
        results.extend(_suggest_fields(partial))
        return sorted(results, key=lambda s: -s["score"])

    if context == "eval_expr":
        results = _suggest_eval_functions(partial)
        results.extend(_suggest_fields(partial))
        return sorted(results, key=lambda s: -s["score"])

    if context == "command_args":
        return _suggest_fields(partial)

    return _suggest_fields(partial)
