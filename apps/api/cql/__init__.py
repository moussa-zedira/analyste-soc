"""CQL (Cyber Query Language) — SIEM query engine for analyste-soc.

Usage::

    from apps.api.cql import execute_cql, validate_cql, autocomplete_cql

    results = execute_cql("event_type=\"auth_failure\" | stats count by src_ip", db)
"""

from __future__ import annotations

from apps.api.cql.lexer import Lexer, Token, TokenType  # noqa: F401
from apps.api.cql.parser import Parser  # noqa: F401
from apps.api.cql.executor import execute_cql, explain_cql  # noqa: F401
from apps.api.cql.validator import validate_cql  # noqa: F401
from apps.api.cql.autocomplete import autocomplete_cql  # noqa: F401

__all__ = [
    "Lexer",
    "Token",
    "TokenType",
    "Parser",
    "execute_cql",
    "explain_cql",
    "validate_cql",
    "autocomplete_cql",
]
