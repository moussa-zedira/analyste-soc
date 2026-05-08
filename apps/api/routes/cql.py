"""CQL API — Cyber Query Language endpoints."""

from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from apps.api.cql.autocomplete import autocomplete_cql
from apps.api.cql.commands import list_commands
from apps.api.cql.executor import (
    EVENT_FIELDS,
    FIELD_ALIASES,
    execute_cql,
    explain_cql,
)
from apps.api.cql.query_library import LIBRARY as QUERY_LIBRARY
from apps.api.cql.saved_queries import (
    CATEGORIES,
    EXAMPLE_QUERIES,
    delete_query,
    get_query,
    list_queries,
    save_query,
    seed_builtin_queries,
)
from apps.api.cql.validator import validate_cql
from apps.api.db.session import get_db
from apps.api.security import require_api_key

router = APIRouter(
    prefix="/cql",
    tags=["CQL"],
    dependencies=[Depends(require_api_key)],
)

# Seed built-in queries on import
seed_builtin_queries()

# ---------------------------------------------------------------------------
# Request / Response schemas
# ---------------------------------------------------------------------------


class CQLSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, description="CQL query string")
    earliest: str | None = Field(None, description="Start time (e.g., -24h, -7d, ISO format)")
    latest: str | None = Field(None, description="End time (e.g., now, ISO format)")
    limit: int = Field(1000, ge=1, le=50000, description="Max results to return")
    offset: int = Field(0, ge=0, description="Result offset for pagination")


class CQLValidateRequest(BaseModel):
    query: str = Field(..., min_length=1)


class CQLAutocompleteRequest(BaseModel):
    query: str = Field("", description="Query text so far")
    cursor_position: int = Field(0, ge=0, description="Cursor position in query text")


class CQLExplainRequest(BaseModel):
    query: str = Field(..., min_length=1)


class SaveQueryRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=200)
    query: str = Field(..., min_length=1)
    description: str = ""
    category: str = "custom"
    tags: list[str] = []
    schedule: str | None = None


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------


@router.post("/search")
def cql_search(
    body: CQLSearchRequest,
    db: Session = Depends(get_db),
) -> dict[str, Any]:
    """Execute a CQL query and return results with metadata."""
    kwargs: dict[str, Any] = {
        "limit": body.limit,
        "offset": body.offset,
    }
    if body.earliest:
        kwargs["default_earliest"] = body.earliest
    if body.latest:
        kwargs["default_latest"] = body.latest

    result = execute_cql(body.query, db, **kwargs)

    if "error" in result.get("metadata", {}):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=result["metadata"]["error"],
        )

    return result


@router.post("/validate")
def cql_validate(body: CQLValidateRequest) -> dict[str, Any]:
    """Validate CQL query syntax and semantics without executing."""
    return validate_cql(body.query)


@router.post("/autocomplete")
def cql_autocomplete(
    body: CQLAutocompleteRequest,
    db: Session = Depends(get_db),
) -> list[dict]:
    """Get autocomplete suggestions for partial CQL query."""
    return autocomplete_cql(body.query, body.cursor_position, db=db)


@router.post("/explain")
def cql_explain(body: CQLExplainRequest) -> dict[str, Any]:
    """Explain query plan without executing."""
    return explain_cql(body.query)


@router.get("/fields")
def cql_fields() -> dict[str, Any]:
    """List all searchable fields with types and descriptions."""
    return {
        "fields": EVENT_FIELDS,
        "aliases": FIELD_ALIASES,
    }


@router.get("/commands")
def cql_commands() -> dict[str, Any]:
    """List all available pipe commands with syntax and examples."""
    return {"commands": list_commands()}


@router.post("/saved")
def cql_save_query(body: SaveQueryRequest) -> dict[str, Any]:
    """Save a CQL query."""
    return save_query(
        name=body.name,
        query=body.query,
        description=body.description,
        category=body.category,
        tags=body.tags,
        schedule=body.schedule,
    )


@router.get("/saved")
def cql_list_saved(
    category: str | None = None,
    tag: str | None = None,
) -> list[dict[str, Any]]:
    """List saved queries, optionally filtered by category or tag."""
    return list_queries(category=category, tag=tag)


@router.get("/saved/{query_id}")
def cql_get_saved(query_id: str) -> dict[str, Any]:
    """Get a saved query by ID."""
    q = get_query(query_id)
    if q is None:
        raise HTTPException(status_code=404, detail="Saved query not found")
    return q


@router.delete("/saved/{query_id}")
def cql_delete_saved(query_id: str) -> dict[str, str]:
    """Delete a saved query."""
    if not delete_query(query_id):
        raise HTTPException(status_code=404, detail="Saved query not found or is built-in")
    return {"status": "deleted"}


@router.get("/history")
def cql_history() -> list[dict]:
    """Return recent query history.

    Note: In production this would be stored per-user in DB/Redis.
    Returns empty list as placeholder.
    """
    return []


@router.get("/examples")
def cql_examples() -> dict[str, Any]:
    """Return example queries organized by use case."""
    return {
        "categories": list(CATEGORIES),
        "examples": EXAMPLE_QUERIES,
    }


@router.get("/library")
def cql_library() -> dict[str, Any]:
    """Retourne la bibliothèque de requêtes CQL prédéfinies (starter pack).

    Chaque entrée contient : id, name, description, category, tags, query,
    builtIn, author. Les utilisateurs peuvent les cloner via /cql/saved.
    """
    return {"queries": QUERY_LIBRARY, "total": len(QUERY_LIBRARY)}
