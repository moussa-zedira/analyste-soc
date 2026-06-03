"""API SIGMA Rules — import, gestion, sync du repo SigmaHQ et evaluation."""

from __future__ import annotations

import logging
import os
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel, ConfigDict
from sqlalchemy.orm import Session

from apps.api.db.session import get_db
from apps.api.detection.sigma_engine import SigmaEngine, import_sigma_rule
from apps.api.models.sigma import SigmaRuleCache
from apps.api.models.sigma_rule import SigmaRule
from apps.api.security import require_api_key

logger = logging.getLogger(__name__)

router = APIRouter(dependencies=[Depends(require_api_key)])

SIGMAHQ_REPO_URL = "https://github.com/SigmaHQ/sigma.git"
SIGMAHQ_CACHE_DIR = os.environ.get("SIGMAHQ_CACHE_DIR", "/data/sigmahq")
# Sous-dossiers interessants : windows/linux/network
SIGMAHQ_TARGET_DIRS = ("rules/windows", "rules/linux", "rules/network")


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


class SigmaSyncRequest(BaseModel):
    min_level: str = "medium"
    repo_url: str | None = None
    cache_dir: str | None = None


class SigmaSyncResult(BaseModel):
    loaded: int
    failed: int
    skipped_unsupported: int
    cache_dir: str


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


# ─────────────────────────────────────────────────────────────────────────────
# Sync : clone/pull du repo SigmaHQ et chargement en cache
# ─────────────────────────────────────────────────────────────────────────────
@router.post("/sync", response_model=SigmaSyncResult)
def sync_sigmahq(
    payload: SigmaSyncRequest | None = None,
    db: Session = Depends(get_db),
) -> SigmaSyncResult:
    """Synchronise les regles SigmaHQ vers la table `sigma_rule_cache`.

    Clone (ou pull) le repo SigmaHQ et charge les regles des dossiers
    windows/linux/network filtrees par `min_level`.
    """
    payload = payload or SigmaSyncRequest()
    repo_url = payload.repo_url or SIGMAHQ_REPO_URL
    cache_dir = Path(payload.cache_dir or SIGMAHQ_CACHE_DIR)

    try:
        _ensure_sigmahq_repo(repo_url, cache_dir)
    except Exception as exc:
        raise HTTPException(status_code=502, detail=f"Failed to fetch SigmaHQ repo: {exc}") from exc

    engine = SigmaEngine()
    loaded = 0
    failed = 0
    skipped = 0
    min_level_rank = {"low": 1, "medium": 2, "high": 3}.get(payload.min_level.lower(), 2)

    existing_ids = {r for (r,) in db.query(SigmaRuleCache.rule_id).all()}

    for sub in SIGMAHQ_TARGET_DIRS:
        target = cache_dir / sub
        if not target.exists():
            continue
        for yml_path in target.rglob("*.yml"):
            try:
                yaml_text = yml_path.read_text(encoding="utf-8")
            except Exception:
                failed += 1
                continue

            try:
                compiled = engine.compile_yaml(yaml_text)
            except Exception:
                skipped += 1
                continue

            rule_level_rank = {"low": 1, "medium": 2, "high": 3}.get(compiled.level, 0)
            if rule_level_rank < min_level_rank:
                skipped += 1
                continue

            if compiled.rule_id in existing_ids:
                continue

            try:
                entry = SigmaRuleCache(
                    rule_id=compiled.rule_id,
                    title=compiled.title,
                    description=compiled.description,
                    level=compiled.level,
                    status=compiled.status,
                    author=compiled.author,
                    logsource_product=compiled.logsource.get("product") or None,
                    logsource_category=compiled.logsource.get("category") or None,
                    logsource_service=compiled.logsource.get("service") or None,
                    yaml_source=yaml_text,
                    lucene_query=compiled.lucene,
                    enabled=True,
                    source_path=str(yml_path.relative_to(cache_dir)),
                )
                db.add(entry)
                existing_ids.add(compiled.rule_id)
                loaded += 1
                if loaded % 200 == 0:
                    db.commit()
            except Exception:
                db.rollback()
                failed += 1

    db.commit()
    return SigmaSyncResult(
        loaded=loaded,
        failed=failed,
        skipped_unsupported=skipped,
        cache_dir=str(cache_dir),
    )


def _ensure_sigmahq_repo(repo_url: str, cache_dir: Path) -> None:
    """Clone le repo si absent, sinon fait `git pull`."""
    cache_dir.parent.mkdir(parents=True, exist_ok=True)
    if (cache_dir / ".git").exists():
        subprocess.run(
            ["git", "-C", str(cache_dir), "pull", "--ff-only", "--depth=1"],
            check=True,
            timeout=300,
            capture_output=True,
        )
        return
    if cache_dir.exists():
        shutil.rmtree(cache_dir, ignore_errors=True)
    subprocess.run(
        ["git", "clone", "--depth=1", repo_url, str(cache_dir)],
        check=True,
        timeout=600,
        capture_output=True,
    )
