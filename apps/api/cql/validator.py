"""CQL Validator — validates query syntax and semantics without executing."""

from __future__ import annotations

from difflib import get_close_matches
from typing import Any

from apps.api.cql.lexer import Lexer, LexerError
from apps.api.cql.parser import (
    ASTNode, BoolOp, Comparison, NotExpr, ParseError, Parser, Query,
)
from apps.api.cql.executor import (
    EVENT_FIELDS, FIELD_ALIASES, _STRING_FIELDS, _NUMERIC_FIELDS, _DATETIME_FIELDS, _resolve_field,
)
from apps.api.cql.commands import get_command


# ---------------------------------------------------------------------------
# Validation result
# ---------------------------------------------------------------------------

def _make_error(msg: str, line: int = 0, col: int = 0, severity: str = "error") -> dict:
    return {"message": msg, "line": line, "col": col, "severity": severity}


# ---------------------------------------------------------------------------
# Operator compatibility
# ---------------------------------------------------------------------------

_STRING_OPERATORS = {"=", "!=", "LIKE", "IN", "NOT IN", "CONTAINS", "STARTSWITH", "ENDSWITH", "MATCHES"}
_NUMERIC_OPERATORS = {"=", "!=", ">", ">=", "<", "<=", "IN", "NOT IN"}
_DATETIME_OPERATORS = {"=", "!=", ">", ">=", "<", "<="}

_ALL_FIELD_NAMES = set(EVENT_FIELDS.keys()) | set(FIELD_ALIASES.keys())


def _check_field(name: str, errors: list[dict], warnings: list[dict], token_line: int = 0, token_col: int = 0) -> None:
    """Check if a field name is valid, add errors/warnings if not."""
    resolved = _resolve_field(name)
    if resolved not in EVENT_FIELDS:
        close = get_close_matches(name.lower(), _ALL_FIELD_NAMES, n=3, cutoff=0.5)
        suggestion = ""
        if close:
            suggestion = f" Did you mean: {', '.join(close)}?"
        errors.append(_make_error(
            f"Unknown field: '{name}'.{suggestion}",
            line=token_line,
            col=token_col,
        ))


def _check_operator(field_name: str, operator: str, errors: list[dict], warnings: list[dict]) -> None:
    """Check operator is compatible with field type."""
    resolved = _resolve_field(field_name)
    if resolved not in EVENT_FIELDS:
        return  # Already reported as unknown field

    if resolved in _NUMERIC_FIELDS:
        if operator not in _NUMERIC_OPERATORS:
            warnings.append(_make_error(
                f"Operator '{operator}' is unusual for numeric field '{field_name}'. "
                f"Suggested: {', '.join(sorted(_NUMERIC_OPERATORS))}",
                severity="warning",
            ))
    elif resolved in _DATETIME_FIELDS:
        if operator not in _DATETIME_OPERATORS:
            warnings.append(_make_error(
                f"Operator '{operator}' may not work well with datetime field '{field_name}'. "
                f"Use earliest=/latest= for time filtering.",
                severity="warning",
            ))
    else:  # string
        if operator in (">", ">=", "<", "<="):
            warnings.append(_make_error(
                f"Comparison operator '{operator}' on string field '{field_name}' may produce unexpected results.",
                severity="warning",
            ))


# ---------------------------------------------------------------------------
# AST validation
# ---------------------------------------------------------------------------

def _validate_ast(node: ASTNode | None, errors: list[dict], warnings: list[dict]) -> None:
    if node is None:
        return

    if isinstance(node, Comparison):
        field_name = node.field.name
        token = None
        if hasattr(node.field, 'parts') and node.field.parts:
            pass
        _check_field(field_name, errors, warnings)
        _check_operator(field_name, node.operator, errors, warnings)

    elif isinstance(node, BoolOp):
        _validate_ast(node.left, errors, warnings)
        _validate_ast(node.right, errors, warnings)

    elif isinstance(node, NotExpr):
        _validate_ast(node.operand, errors, warnings)


def _validate_commands(commands: list, errors: list[dict], warnings: list[dict]) -> None:
    for cmd in commands:
        if get_command(cmd.name) is None:
            close = get_close_matches(cmd.name, list(_KNOWN_COMMANDS), n=2, cutoff=0.5)
            suggestion = f" Did you mean: {', '.join(close)}?" if close else ""
            errors.append(_make_error(f"Unknown command: '{cmd.name}'.{suggestion}"))

        # Command-specific validation
        if cmd.name == "stats" and not cmd.raw_text.strip():
            errors.append(_make_error("'stats' command requires at least one aggregation function."))

        if cmd.name in ("head", "tail"):
            parts = cmd.raw_text.strip().split()
            if parts:
                try:
                    n = int(parts[0])
                    if n <= 0:
                        errors.append(_make_error(f"'{cmd.name}' requires a positive number, got {n}."))
                except ValueError:
                    errors.append(_make_error(f"'{cmd.name}' argument must be a number, got '{parts[0]}'."))

        if cmd.name == "sort" and not cmd.raw_text.strip():
            errors.append(_make_error("'sort' command requires a field name."))

        if cmd.name == "rename":
            if "AS" not in cmd.raw_text.upper():
                warnings.append(_make_error(
                    "'rename' expects syntax: rename <old> as <new>",
                    severity="warning",
                ))

        if cmd.name == "trendline":
            parts = cmd.raw_text.strip().split()
            if len(parts) < 3:
                errors.append(_make_error("'trendline' requires: trendline <type> <span> <field>"))
            elif parts[0].lower() not in ("sma", "ema", "wma"):
                errors.append(_make_error(f"Unknown trendline type: '{parts[0]}'. Use sma, ema, or wma."))


from apps.api.cql.commands import list_commands
_KNOWN_COMMANDS = set(list_commands().keys())


# ---------------------------------------------------------------------------
# Main validator
# ---------------------------------------------------------------------------

def validate_cql(query_str: str) -> dict[str, Any]:
    """Validate a CQL query without executing it.

    Returns::

        {
            "valid": bool,
            "errors": [{"message": str, "line": int, "col": int, "severity": "error"}],
            "warnings": [{"message": str, "line": int, "col": int, "severity": "warning"}],
        }
    """
    errors: list[dict] = []
    warnings: list[dict] = []

    if not query_str or not query_str.strip():
        return {"valid": False, "errors": [_make_error("Empty query")], "warnings": []}

    # Lexer phase
    try:
        lexer = Lexer(query_str)
        tokens = lexer.tokenize()
    except LexerError as exc:
        return {
            "valid": False,
            "errors": [_make_error(str(exc), line=exc.line, col=exc.col)],
            "warnings": [],
        }

    # Parser phase
    try:
        parser = Parser(tokens)
        ast = parser.parse()
    except ParseError as exc:
        return {
            "valid": False,
            "errors": [_make_error(str(exc))],
            "warnings": [],
        }

    # Semantic validation
    _validate_ast(ast.filter_expr, errors, warnings)
    _validate_commands(ast.commands, errors, warnings)

    # Time range validation
    if ast.earliest:
        import re
        if not re.match(r"^-\d+(s|m|h|d|w)$", ast.earliest) and ast.earliest.lower() != "now":
            try:
                from datetime import datetime
                datetime.fromisoformat(ast.earliest)
            except (ValueError, TypeError):
                errors.append(_make_error(
                    f"Invalid earliest time: '{ast.earliest}'. "
                    "Use relative (-24h, -7d) or ISO format (2026-03-28T00:00:00)."
                ))

    if ast.latest:
        import re
        if not re.match(r"^-\d+(s|m|h|d|w)$", ast.latest) and ast.latest.lower() != "now":
            try:
                from datetime import datetime
                datetime.fromisoformat(ast.latest)
            except (ValueError, TypeError):
                errors.append(_make_error(
                    f"Invalid latest time: '{ast.latest}'. "
                    "Use relative (-24h) or ISO format or 'now'."
                ))

    # Performance warnings
    if not ast.earliest and not ast.latest:
        warnings.append(_make_error(
            "No time range specified. Defaults to last 24h. Use earliest= for wider range.",
            severity="warning",
        ))

    has_limit = any(cmd.name in ("head", "tail") for cmd in ast.commands)
    has_stats = any(cmd.name == "stats" for cmd in ast.commands)
    if not has_limit and not has_stats and not ast.commands:
        warnings.append(_make_error(
            "No limit specified. Large result sets may be slow. Consider adding '| head 100'.",
            severity="warning",
        ))

    return {
        "valid": len(errors) == 0,
        "errors": errors,
        "warnings": warnings,
    }
