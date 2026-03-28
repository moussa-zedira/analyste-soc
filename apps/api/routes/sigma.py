"""API SIGMA Rules — import, gestion et evaluation des regles SIGMA."""

from __future__ import annotations

from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.detection.sigma_engine import import_sigma_rule
from apps.api.models.sigma_rule import SigmaRule
from apps.api.security import require_api_key

router = APIRouter(dependencies=[Depends(require_api_key)])


class SigmaRuleRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    description: str | None
    level: str
    enabled: bool
    author: str | None
    created_at: datetime


class SigmaImportRequest(BaseModel):
    yaml_content: str


class SigmaToggleRequest(BaseModel):
    enabled: bool


@router.post("/import", response_model=SigmaRuleRead, status_code=status.HTTP_201_CREATED)
def import_rule(
    payload: SigmaImportRequest,
    db: Session = Depends(get_db),
) -> SigmaRule:
    """Importe une regle SIGMA depuis du YAML."""
    try:
        rule = import_sigma_rule(payload.yaml_content, db)
        return rule
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))


@router.get("", response_model=list[SigmaRuleRead])
def list_rules(
    enabled_only: bool = False,
    db: Session = Depends(get_db),
) -> list[SigmaRule]:
    """Liste les regles SIGMA importees."""
    query = db.query(SigmaRule)
    if enabled_only:
        query = query.filter(SigmaRule.enabled.is_(True))
    return query.order_by(SigmaRule.created_at.desc()).all()


@router.patch("/{rule_id}", response_model=SigmaRuleRead)
def toggle_rule(
    rule_id: int,
    payload: SigmaToggleRequest,
    db: Session = Depends(get_db),
) -> SigmaRule:
    """Active ou desactive une regle SIGMA."""
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.enabled = payload.enabled
    db.commit()
    db.refresh(rule)
    return rule


@router.delete("/{rule_id}", status_code=status.HTTP_204_NO_CONTENT)
def delete_rule(
    rule_id: int,
    db: Session = Depends(get_db),
) -> None:
    """Supprime une regle SIGMA."""
    rule = db.get(SigmaRule, rule_id)
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    db.delete(rule)
    db.commit()
