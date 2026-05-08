"""CQL Pipe Commands — transform, aggregate, and enrich query results."""

from __future__ import annotations

import contextlib
import re
import statistics
from collections import Counter, defaultdict
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from typing import Any

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _safe_float(v: Any) -> float | None:
    if v is None:
        return None
    try:
        return float(v)
    except (ValueError, TypeError):
        return None


def _parse_timespan(s: str) -> timedelta | None:
    """Parse time span like 1m, 5m, 1h, 1d, 30s into timedelta."""
    m = re.match(r"^(\d+)(s|m|h|d|w)$", s.strip())
    if not m:
        return None
    val, unit = int(m.group(1)), m.group(2)
    mapping = {"s": "seconds", "m": "minutes", "h": "hours", "d": "days", "w": "weeks"}
    return timedelta(**{mapping[unit]: val})


def _get_field(row: dict, field: str) -> Any:
    """Get field value with dot-notation support."""
    if "." in field:
        parts = field.split(".")
        cur = row
        for p in parts:
            if isinstance(cur, dict):
                cur = cur.get(p)
            else:
                return None
        return cur
    return row.get(field)


def _set_field(row: dict, field: str, value: Any) -> None:
    row[field] = value


def _bucket_time(ts: datetime, span: timedelta) -> str:
    """Bucket a timestamp to the nearest span boundary."""
    epoch = datetime(2000, 1, 1, tzinfo=UTC)
    delta = ts - epoch
    seconds = delta.total_seconds()
    span_secs = span.total_seconds()
    bucket_start = epoch + timedelta(seconds=int(seconds // span_secs) * span_secs)
    return bucket_start.isoformat()


# ---------------------------------------------------------------------------
# Command registry
# ---------------------------------------------------------------------------

_COMMANDS: dict[str, Callable] = {}


def register_command(name: str) -> Callable:
    def decorator(fn: Callable) -> Callable:
        _COMMANDS[name] = fn
        return fn
    return decorator


def get_command(name: str) -> Callable | None:
    return _COMMANDS.get(name)


def list_commands() -> dict[str, dict]:
    """Return command metadata for documentation."""
    return {
        name: {
            "name": name,
            "description": fn.__doc__ or "",
            "syntax": _COMMAND_SYNTAX.get(name, f"| {name} ..."),
            "examples": _COMMAND_EXAMPLES.get(name, []),
        }
        for name, fn in sorted(_COMMANDS.items())
    }


# ---------------------------------------------------------------------------
# Command implementations
# ---------------------------------------------------------------------------

@register_command("where")
def cmd_where(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Filter results with an additional condition."""
    if not raw_text.strip():
        return rows
    # Parse simple conditions: field op value
    parts = raw_text.strip().split()
    if len(parts) < 3:
        return rows

    field = parts[0]
    op = parts[1]
    value_str = " ".join(parts[2:]).strip("'\"")

    result = []
    for row in rows:
        fval = _get_field(row, field)
        if fval is None:
            continue
        try:
            if op == ">" and _safe_float(fval) is not None and _safe_float(fval) > float(value_str) or op == ">=" and _safe_float(fval) is not None and _safe_float(fval) >= float(value_str) or op == "<" and _safe_float(fval) is not None and _safe_float(fval) < float(value_str) or op == "<=" and _safe_float(fval) is not None and _safe_float(fval) <= float(value_str) or op in ("=", "==") and str(fval) == value_str or op == "!=" and str(fval) != value_str or op.upper() == "CONTAINS" and value_str.lower() in str(fval).lower():
                result.append(row)
        except (ValueError, TypeError):
            continue
    return result


@register_command("stats")
def cmd_stats(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Aggregate results: stats <agg_func>(<field>) [as alias] by <field1>, <field2>."""
    # Parse: <agg_func> [by <field1>, <field2>]
    text = raw_text.strip()

    # Find "by" keyword to split aggregations and group-by fields
    by_idx = None
    parts = text.split()
    for i, p in enumerate(parts):
        if p.lower() == "by":
            by_idx = i
            break

    if by_idx is not None:
        agg_part = " ".join(parts[:by_idx])
        group_fields = [f.strip().strip(",") for f in parts[by_idx + 1:] if f.strip().strip(",")]
    else:
        agg_part = text
        group_fields = []

    # Parse aggregation functions
    agg_specs = _parse_agg_specs(agg_part)

    # Group rows
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for row in rows:
        key = tuple(_get_field(row, gf) for gf in group_fields) if group_fields else ((),)
        groups[key].append(row)

    # Compute aggregates
    result = []
    for key, group in groups.items():
        out: dict[str, Any] = {}
        if group_fields:
            for i, gf in enumerate(group_fields):
                out[gf] = key[i]

        for agg_name, agg_field, alias in agg_specs:
            val = _compute_agg(agg_name, agg_field, group)
            col_name = alias or f"{agg_name}_{agg_field}" if agg_field else alias or agg_name
            out[col_name] = val
        result.append(out)

    return result


def _parse_agg_specs(text: str) -> list[tuple[str, str, str]]:
    """Parse aggregation specifications like 'count, sum(bytes) as total'."""
    specs = []
    # Split by comma, respecting parentheses
    parts = re.split(r",\s*(?![^()]*\))", text)
    for part in parts:
        part = part.strip()
        if not part:
            continue

        alias = ""
        if " as " in part.lower():
            idx = part.lower().index(" as ")
            alias = part[idx + 4:].strip()
            part = part[:idx].strip()

        m = re.match(r"(\w+)\(([^)]*)\)", part)
        if m:
            func_name = m.group(1).lower()
            field = m.group(2).strip()
            specs.append((func_name, field, alias))
        else:
            # Simple: "count" means count()
            specs.append((part.lower(), "", alias))
    return specs


def _compute_agg(func: str, field: str, rows: list[dict]) -> Any:
    """Compute a single aggregation function over rows."""
    if func == "count":
        if field:
            return sum(1 for r in rows if _get_field(r, field) is not None)
        return len(rows)

    values = [_get_field(r, field) for r in rows if _get_field(r, field) is not None]

    if func == "sum":
        nums = [_safe_float(v) for v in values if _safe_float(v) is not None]
        return sum(nums) if nums else 0

    if func == "avg":
        nums = [_safe_float(v) for v in values if _safe_float(v) is not None]
        return statistics.mean(nums) if nums else 0

    if func == "min":
        nums = [_safe_float(v) for v in values if _safe_float(v) is not None]
        return min(nums) if nums else None

    if func == "max":
        nums = [_safe_float(v) for v in values if _safe_float(v) is not None]
        return max(nums) if nums else None

    if func in ("dc", "distinct_count"):
        return len({str(v) for v in values})

    if func == "values":
        return list({str(v) for v in values})

    if func == "first":
        return values[0] if values else None

    if func == "last":
        return values[-1] if values else None

    return len(rows)


@register_command("sort")
def cmd_sort(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Sort results: sort <field> [asc|desc]."""
    parts = raw_text.strip().split()
    if not parts:
        return rows
    field = parts[0]
    desc = len(parts) > 1 and parts[1].lower() == "desc"

    def sort_key(row: dict) -> Any:
        v = _get_field(row, field)
        if v is None:
            return (1, "")  # nulls last
        fv = _safe_float(v)
        if fv is not None:
            return (0, fv)
        return (0, str(v))

    return sorted(rows, key=sort_key, reverse=desc)


@register_command("head")
def cmd_head(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Return first N results (default 10)."""
    n = 10
    parts = raw_text.strip().split()
    if parts:
        with contextlib.suppress(ValueError):
            n = int(parts[0])
    return rows[:n]


@register_command("tail")
def cmd_tail(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Return last N results (default 10)."""
    n = 10
    parts = raw_text.strip().split()
    if parts:
        with contextlib.suppress(ValueError):
            n = int(parts[0])
    return rows[-n:] if len(rows) >= n else rows


@register_command("unique")
def cmd_unique(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Deduplicate by field value."""
    field = raw_text.strip()
    if not field:
        return rows
    seen: set = set()
    result = []
    for row in rows:
        val = str(_get_field(row, field))
        if val not in seen:
            seen.add(val)
            result.append(row)
    return result


@register_command("timechart")
def cmd_timechart(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Time-based aggregation: timechart span=<interval> <agg> [by <field>]."""
    text = raw_text.strip()
    span = timedelta(hours=1)  # default

    # Extract span=
    span_match = re.search(r"span=(\S+)", text)
    if span_match:
        parsed = _parse_timespan(span_match.group(1))
        if parsed:
            span = parsed
        text = text[:span_match.start()] + text[span_match.end():]

    # Parse remaining: <agg> [by <field>]
    parts = text.strip().split()
    by_idx = None
    for i, p in enumerate(parts):
        if p.lower() == "by":
            by_idx = i
            break

    if by_idx is not None:
        agg_part = " ".join(parts[:by_idx])
        split_field = parts[by_idx + 1] if by_idx + 1 < len(parts) else None
    else:
        agg_part = " ".join(parts)
        split_field = None

    agg_specs = _parse_agg_specs(agg_part) if agg_part.strip() else [("count", "", "")]

    # Bucket by time
    buckets: dict[str, dict[str, list[dict]]] = defaultdict(lambda: defaultdict(list))
    for row in rows:
        ts = row.get("ts")
        if isinstance(ts, str):
            try:
                ts = datetime.fromisoformat(ts)
            except (ValueError, TypeError):
                continue
        if not isinstance(ts, datetime):
            continue
        bucket_key = _bucket_time(ts, span)
        split_key = str(_get_field(row, split_field)) if split_field else "_all"
        buckets[bucket_key][split_key].append(row)

    result = []
    for bucket_key in sorted(buckets.keys()):
        for split_key, group in buckets[bucket_key].items():
            out: dict[str, Any] = {"_time": bucket_key}
            if split_field:
                out[split_field] = split_key
            for agg_name, agg_field, alias in agg_specs:
                val = _compute_agg(agg_name, agg_field, group)
                col_name = alias or (f"{agg_name}_{agg_field}" if agg_field else agg_name)
                out[col_name] = val
            result.append(out)
    return result


@register_command("regex")
def cmd_regex(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Filter by regex: regex field=<field> "<pattern>"."""
    text = raw_text.strip()
    field_match = re.match(r'field=(\S+)\s+["\']?(.+?)["\']?\s*$', text)
    if not field_match:
        return rows
    field = field_match.group(1)
    pattern = field_match.group(2)
    try:
        compiled = re.compile(pattern, re.IGNORECASE)
    except re.error:
        return rows
    return [r for r in rows if compiled.search(str(_get_field(r, field) or ""))]


@register_command("eval")
def cmd_eval(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Compute new fields: eval <field> = <expression>."""
    text = raw_text.strip()
    eq_idx = text.find("=")
    if eq_idx < 1:
        return rows
    target_field = text[:eq_idx].strip()
    expression = text[eq_idx + 1:].strip()

    for row in rows:
        row[target_field] = _eval_expression(expression, row)
    return rows


def _eval_expression(expr: str, row: dict) -> Any:
    """Evaluate a simple expression in the context of a row."""
    expr = expr.strip()

    # if(condition, true_val, false_val)
    if_match = re.match(r'if\((.+?),\s*(.+?),\s*(.+?)\)\s*$', expr)
    if if_match:
        cond, tv, fv = if_match.group(1), if_match.group(2).strip(), if_match.group(3).strip()
        cond_parts = cond.split()
        if len(cond_parts) >= 3:
            left = _resolve_val(cond_parts[0], row)
            op = cond_parts[1]
            right = _resolve_val(" ".join(cond_parts[2:]), row)
            cond_result = _eval_condition(left, op, right)
        else:
            cond_result = bool(_resolve_val(cond, row))
        return _resolve_val(tv, row) if cond_result else _resolve_val(fv, row)

    # len(field)
    len_match = re.match(r'len\((\w+)\)', expr)
    if len_match:
        v = _get_field(row, len_match.group(1))
        return len(str(v)) if v is not None else 0

    # lower(field)
    lower_match = re.match(r'lower\((\w+)\)', expr)
    if lower_match:
        v = _get_field(row, lower_match.group(1))
        return str(v).lower() if v is not None else ""

    # upper(field)
    upper_match = re.match(r'upper\((\w+)\)', expr)
    if upper_match:
        v = _get_field(row, upper_match.group(1))
        return str(v).upper() if v is not None else ""

    # substr(field, start, length)
    substr_match = re.match(r'substr\((\w+),\s*(\d+),\s*(\d+)\)', expr)
    if substr_match:
        v = str(_get_field(row, substr_match.group(1)) or "")
        start, length = int(substr_match.group(2)), int(substr_match.group(3))
        return v[start:start + length]

    # replace(field, pattern, replacement)
    replace_match = re.match(r'replace\((\w+),\s*["\'](.+?)["\']\s*,\s*["\'](.*)["\']\)', expr)
    if replace_match:
        v = str(_get_field(row, replace_match.group(1)) or "")
        return v.replace(replace_match.group(2), replace_match.group(3))

    # concat(...)
    concat_match = re.match(r'concat\((.+)\)', expr)
    if concat_match:
        parts = [p.strip() for p in concat_match.group(1).split(",")]
        return "".join(str(_resolve_val(p, row) or "") for p in parts)

    # now()
    if expr.strip() == "now()":
        return datetime.now(UTC).isoformat()

    # Simple arithmetic: field + field, field - field, etc.
    for op in ["+", "-", "*", "/"]:
        if op in expr:
            parts = expr.split(op, 1)
            left = _resolve_val(parts[0].strip(), row)
            right = _resolve_val(parts[1].strip(), row)
            lf, rf = _safe_float(left), _safe_float(right)
            if lf is not None and rf is not None:
                if op == "+":
                    return lf + rf
                if op == "-":
                    return lf - rf
                if op == "*":
                    return lf * rf
                if op == "/" and rf != 0:
                    return lf / rf
            if op == "+":
                return str(left or "") + str(right or "")
            break

    # String concatenation with . operator
    if "." in expr and not expr[0].isdigit():
        parts = expr.split(".", 1)
        left = _resolve_val(parts[0].strip(), row)
        right = _resolve_val(parts[1].strip(), row)
        return str(left or "") + str(right or "")

    return _resolve_val(expr, row)


def _resolve_val(v: str, row: dict) -> Any:
    """Resolve a value: quoted string -> string, number -> number, else field lookup."""
    v = v.strip()
    if (v.startswith('"') and v.endswith('"')) or (v.startswith("'") and v.endswith("'")):
        return v[1:-1]
    try:
        return int(v)
    except ValueError:
        pass
    try:
        return float(v)
    except ValueError:
        pass
    return _get_field(row, v)


def _eval_condition(left: Any, op: str, right: Any) -> bool:
    try:
        lf, rf = _safe_float(left), _safe_float(right)
        if lf is not None and rf is not None:
            if op == ">":
                return lf > rf
            if op == ">=":
                return lf >= rf
            if op == "<":
                return lf < rf
            if op == "<=":
                return lf <= rf
            if op in ("=", "=="):
                return lf == rf
            if op == "!=":
                return lf != rf
        return str(left) == str(right) if op in ("=", "==") else str(left) != str(right)
    except (TypeError, ValueError):
        return False


@register_command("rename")
def cmd_rename(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Rename fields: rename <old> as <new>."""
    parts = raw_text.strip().split()
    # Support multiple renames: rename old1 as new1, old2 as new2
    renames: list[tuple[str, str]] = []
    i = 0
    while i < len(parts):
        old = parts[i]
        if i + 2 < len(parts) and parts[i + 1].upper() == "AS":
            new = parts[i + 2].strip(",")
            renames.append((old, new))
            i += 3
        else:
            i += 1
        # Skip commas
        if i < len(parts) and parts[i] == ",":
            i += 1

    for row in rows:
        for old, new in renames:
            if old in row:
                row[new] = row.pop(old)
    return rows


@register_command("fields")
def cmd_fields(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Select or exclude fields: fields [+|-] <field1>, <field2>."""
    parts = [f.strip().strip(",") for f in raw_text.strip().split() if f.strip().strip(",")]
    if not parts:
        return rows

    exclude = parts[0].startswith("-")
    parts[0].startswith("+")

    if exclude:
        fields_list = [p.lstrip("-").strip(",") for p in parts]
        return [{k: v for k, v in row.items() if k not in fields_list} for row in rows]
    else:
        fields_list = [p.lstrip("+").strip(",") for p in parts]
        return [{f: row.get(f) for f in fields_list} for row in rows]


@register_command("table")
def cmd_table(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Format as table (alias for fields): table <field1>, <field2>."""
    return cmd_fields(rows, args, raw_text)


@register_command("dedup")
def cmd_dedup(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Deduplicate, keeping first occurrence: dedup <field> [sortby=<field>]."""
    parts = raw_text.strip().split()
    if not parts:
        return rows

    dedup_field = parts[0]
    sort_field = None
    for p in parts[1:]:
        if p.startswith("sortby="):
            sort_field = p.split("=", 1)[1]

    if sort_field:
        rows = sorted(rows, key=lambda r: str(_get_field(r, sort_field) or ""))

    seen: set = set()
    result = []
    for row in rows:
        val = str(_get_field(row, dedup_field))
        if val not in seen:
            seen.add(val)
            result.append(row)
    return result


@register_command("lookup")
def cmd_lookup(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Enrich with lookup table: lookup <lookup_name> <field>."""
    # Placeholder — in production this would load a lookup CSV/table
    return rows


@register_command("join")
def cmd_join(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Join with subsearch: join type=<inner|left|outer> <field> [subsearch].

    Note: subsearch execution requires the full executor context; this is a stub
    that returns rows unmodified when no subsearch context is available.
    """
    return rows


@register_command("transaction")
def cmd_transaction(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Group events into transactions: transaction <field> [maxspan=<time>]."""
    parts = raw_text.strip().split()
    if not parts:
        return rows

    field = parts[0]
    maxspan = timedelta(hours=1)
    for p in parts[1:]:
        if p.startswith("maxspan="):
            parsed = _parse_timespan(p.split("=", 1)[1])
            if parsed:
                maxspan = parsed

    # Group by field value
    groups: dict[str, list[dict]] = defaultdict(list)
    for row in rows:
        key = str(_get_field(row, field) or "_null")
        groups[key].append(row)

    result = []
    for key, events in groups.items():
        # Sort events by time
        events.sort(key=lambda r: str(r.get("ts", "")))

        # Split into transactions based on maxspan
        tx_events: list[dict] = []
        tx_start: datetime | None = None
        for evt in events:
            ts = evt.get("ts")
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    ts = None

            if tx_start and ts and isinstance(ts, datetime) and (ts - tx_start) > maxspan:
                # Close current transaction, start new one
                if tx_events:
                    result.append({
                        field: key,
                        "event_count": len(tx_events),
                        "duration": str(ts - tx_start) if tx_start else "0",
                        "events": tx_events,
                    })
                tx_events = [evt]
                tx_start = ts
            else:
                tx_events.append(evt)
                if tx_start is None and isinstance(ts, datetime):
                    tx_start = ts

        if tx_events:
            last_ts = tx_events[-1].get("ts")
            if isinstance(last_ts, str):
                try:
                    last_ts = datetime.fromisoformat(last_ts)
                except (ValueError, TypeError):
                    last_ts = tx_start
            dur = str(last_ts - tx_start) if tx_start and isinstance(last_ts, datetime) else "0"
            result.append({
                field: key,
                "event_count": len(tx_events),
                "duration": dur,
                "events": tx_events,
            })

    return result


@register_command("bucket")
def cmd_bucket(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Bucket numeric/time values: bucket <field> span=<value>."""
    parts = raw_text.strip().split()
    if not parts:
        return rows

    field = parts[0]
    span_str = "1h"
    for p in parts[1:]:
        if p.startswith("span="):
            span_str = p.split("=", 1)[1]

    span = _parse_timespan(span_str)
    if span:
        # Time bucketing
        for row in rows:
            ts = row.get(field)
            if isinstance(ts, str):
                try:
                    ts = datetime.fromisoformat(ts)
                except (ValueError, TypeError):
                    continue
            if isinstance(ts, datetime):
                row[field] = _bucket_time(ts, span)
    else:
        # Numeric bucketing
        try:
            bucket_size = float(span_str)
        except ValueError:
            return rows
        for row in rows:
            v = _safe_float(_get_field(row, field))
            if v is not None:
                row[field] = int(v // bucket_size) * bucket_size

    return rows


@register_command("top")
def cmd_top(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Top N values by count: top <n> <field>."""
    parts = raw_text.strip().split()
    n = 10
    field = ""
    if len(parts) >= 2:
        try:
            n = int(parts[0])
            field = parts[1]
        except ValueError:
            field = parts[0]
    elif len(parts) == 1:
        field = parts[0]

    if not field:
        return rows

    counter = Counter(str(_get_field(r, field)) for r in rows if _get_field(r, field) is not None)
    return [
        {field: val, "count": cnt, "percent": round(cnt / len(rows) * 100, 2) if rows else 0}
        for val, cnt in counter.most_common(n)
    ]


@register_command("rare")
def cmd_rare(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Least common N values: rare <n> <field>."""
    parts = raw_text.strip().split()
    n = 10
    field = ""
    if len(parts) >= 2:
        try:
            n = int(parts[0])
            field = parts[1]
        except ValueError:
            field = parts[0]
    elif len(parts) == 1:
        field = parts[0]

    if not field:
        return rows

    counter = Counter(str(_get_field(r, field)) for r in rows if _get_field(r, field) is not None)
    return [
        {field: val, "count": cnt, "percent": round(cnt / len(rows) * 100, 2) if rows else 0}
        for val, cnt in counter.most_common()[:-n - 1:-1]
    ]


@register_command("iplocation")
def cmd_iplocation(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Add geo info from IP field: iplocation <field>."""
    field = raw_text.strip() or "src_ip"
    # Placeholder — integrate with GeoIP database in production
    for row in rows:
        ip = _get_field(row, field)
        if ip:
            row["country"] = row.get("country", "Unknown")
            row["city"] = row.get("city", "Unknown")
            row["lat"] = row.get("lat", 0.0)
            row["lon"] = row.get("lon", 0.0)
    return rows


@register_command("mitre")
def cmd_mitre(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Add MITRE ATT&CK technique info: mitre <field>."""
    # Map common event types to MITRE techniques
    technique_map: dict[str, dict] = {
        "auth_failure": {"technique_id": "T1110", "technique": "Brute Force", "tactic": "Credential Access"},
        "process_create": {"technique_id": "T1059", "technique": "Command and Scripting Interpreter", "tactic": "Execution"},
        "privilege_change": {"technique_id": "T1548", "technique": "Abuse Elevation Control Mechanism", "tactic": "Privilege Escalation"},
        "rdp_connect": {"technique_id": "T1021.001", "technique": "Remote Desktop Protocol", "tactic": "Lateral Movement"},
        "ssh_connect": {"technique_id": "T1021.004", "technique": "SSH", "tactic": "Lateral Movement"},
        "smb_connect": {"technique_id": "T1021.002", "technique": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
        "dns_query": {"technique_id": "T1071.004", "technique": "DNS", "tactic": "Command and Control"},
        "file_create": {"technique_id": "T1105", "technique": "Ingress Tool Transfer", "tactic": "Command and Control"},
        "registry_modify": {"technique_id": "T1112", "technique": "Modify Registry", "tactic": "Defense Evasion"},
        "scheduled_task": {"technique_id": "T1053", "technique": "Scheduled Task/Job", "tactic": "Persistence"},
        "service_install": {"technique_id": "T1543", "technique": "Create or Modify System Process", "tactic": "Persistence"},
    }
    field = raw_text.strip() or "event_type"
    for row in rows:
        val = str(_get_field(row, field) or "")
        if val in technique_map:
            row.update(technique_map[val])
        else:
            row["technique_id"] = ""
            row["technique"] = ""
            row["tactic"] = ""
    return rows


@register_command("trendline")
def cmd_trendline(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Add trend calculation: trendline <type> <span> <field>."""
    parts = raw_text.strip().split()
    if len(parts) < 3:
        return rows

    trend_type = parts[0].lower()  # sma, ema, wma
    try:
        span = int(parts[1])
    except ValueError:
        span = 5
    field = parts[2]

    values = [_safe_float(_get_field(r, field)) for r in rows]
    trend_col = f"{trend_type}{span}_{field}"

    if trend_type == "sma":
        for i, row in enumerate(rows):
            if i < span - 1:
                row[trend_col] = None
            else:
                window = [v for v in values[i - span + 1:i + 1] if v is not None]
                row[trend_col] = statistics.mean(window) if window else None

    elif trend_type == "ema":
        multiplier = 2 / (span + 1)
        ema = None
        for i, row in enumerate(rows):
            v = values[i]
            if v is None:
                row[trend_col] = ema
                continue
            if ema is None:
                ema = v
            else:
                ema = (v - ema) * multiplier + ema
            row[trend_col] = round(ema, 4) if ema is not None else None

    elif trend_type == "wma":
        for i, row in enumerate(rows):
            if i < span - 1:
                row[trend_col] = None
            else:
                window = [(j + 1, values[i - span + 1 + j]) for j in range(span) if values[i - span + 1 + j] is not None]
                if window:
                    total_weight = sum(w for w, _ in window)
                    row[trend_col] = round(sum(w * v for w, v in window) / total_weight, 4) if total_weight else None
                else:
                    row[trend_col] = None

    return rows


@register_command("fillnull")
def cmd_fillnull(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Fill null values: fillnull [value=<val>] [<field1>, <field2>]."""
    text = raw_text.strip()
    fill_value: Any = 0
    fields: list[str] = []

    value_match = re.match(r'value=(\S+)\s*(.*)', text)
    if value_match:
        fill_value = value_match.group(1).strip("'\"")
        remaining = value_match.group(2)
        fields = [f.strip().strip(",") for f in remaining.split() if f.strip().strip(",")]
    else:
        parts = [f.strip().strip(",") for f in text.split() if f.strip().strip(",")]
        fields = parts

    for row in rows:
        target_fields = fields if fields else list(row.keys())
        for f in target_fields:
            if f in row and row[f] is None:
                row[f] = fill_value
    return rows


@register_command("mvexpand")
def cmd_mvexpand(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Expand multi-value field into multiple rows: mvexpand <field>."""
    field = raw_text.strip()
    if not field:
        return rows

    result = []
    for row in rows:
        val = _get_field(row, field)
        if isinstance(val, (list, tuple)):
            for item in val:
                new_row = dict(row)
                new_row[field] = item
                result.append(new_row)
        elif isinstance(val, str) and "," in val:
            for item in val.split(","):
                new_row = dict(row)
                new_row[field] = item.strip()
                result.append(new_row)
        else:
            result.append(row)
    return result


@register_command("outputlookup")
def cmd_outputlookup(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Save results as lookup table: outputlookup <name>.

    Note: actual persistence requires filesystem/DB context. This is a stub.
    """
    return rows


@register_command("append")
def cmd_append(rows: list[dict], args: list[str], raw_text: str) -> list[dict]:
    """Append subsearch results: append [subsearch].

    Note: subsearch execution requires the full executor context.
    """
    return rows


# ---------------------------------------------------------------------------
# Command metadata for documentation
# ---------------------------------------------------------------------------

_COMMAND_SYNTAX: dict[str, str] = {
    "where": "| where <field> <op> <value>",
    "stats": "| stats <func>(<field>) [as <alias>] [by <field1>, <field2>]",
    "sort": "| sort <field> [asc|desc]",
    "head": "| head [<n>]",
    "tail": "| tail [<n>]",
    "unique": "| unique <field>",
    "timechart": "| timechart span=<interval> <func>(<field>) [by <split_field>]",
    "regex": '| regex field=<field> "<pattern>"',
    "eval": "| eval <new_field> = <expression>",
    "rename": "| rename <old_name> as <new_name>",
    "fields": "| fields [+|-] <field1>, <field2>, ...",
    "table": "| table <field1>, <field2>, ...",
    "dedup": "| dedup <field> [sortby=<field>]",
    "lookup": "| lookup <lookup_name> <field>",
    "join": "| join type=<inner|left|outer> <field> [subsearch]",
    "transaction": "| transaction <field> [maxspan=<time>]",
    "bucket": "| bucket <field> span=<value>",
    "top": "| top <n> <field>",
    "rare": "| rare <n> <field>",
    "iplocation": "| iplocation <field>",
    "mitre": "| mitre <field>",
    "trendline": "| trendline <sma|ema|wma> <span> <field>",
    "fillnull": "| fillnull [value=<val>] [<field1>, <field2>]",
    "mvexpand": "| mvexpand <field>",
    "outputlookup": "| outputlookup <name>",
    "append": "| append [subsearch]",
}

_COMMAND_EXAMPLES: dict[str, list[str]] = {
    "where": ["| where count > 10", "| where severity = high"],
    "stats": [
        "| stats count by src_ip",
        "| stats count, avg(ti_score) by event_type",
        "| stats dc(src_ip) as unique_sources by dst_ip",
    ],
    "sort": ["| sort count desc", "| sort ts asc"],
    "head": ["| head 20", "| head"],
    "tail": ["| tail 5"],
    "unique": ["| unique src_ip"],
    "timechart": [
        "| timechart span=1h count by severity",
        "| timechart span=5m count",
    ],
    "regex": ['| regex field=message "powershell.*-enc"'],
    "eval": [
        '| eval risk = ti_score * 10',
        '| eval label = if(severity = "high", "CRITICAL", "normal")',
    ],
    "rename": ["| rename src_ip as source_address"],
    "fields": ["| fields src_ip, dst_ip, severity", "| fields - raw, id"],
    "table": ["| table ts, src_ip, event_type, severity"],
    "dedup": ["| dedup src_ip sortby=ts"],
    "top": ["| top 10 src_ip", "| top 5 event_type"],
    "rare": ["| rare 10 event_type"],
    "iplocation": ["| iplocation src_ip"],
    "mitre": ["| mitre event_type"],
    "trendline": ["| trendline sma 5 count"],
    "fillnull": ["| fillnull value=0 ti_score", "| fillnull"],
    "mvexpand": ["| mvexpand ti_tags"],
    "transaction": ["| transaction src_ip maxspan=5m"],
    "bucket": ["| bucket ts span=1h"],
}


def execute_command(
    name: str,
    rows: list[dict],
    args: list[str],
    raw_text: str,
) -> list[dict]:
    """Execute a named pipe command against a result set."""
    fn = get_command(name)
    if fn is None:
        raise ValueError(f"Unknown pipe command: {name}")
    return fn(rows, args, raw_text)
