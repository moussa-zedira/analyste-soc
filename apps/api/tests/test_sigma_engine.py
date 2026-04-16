"""Tests SIGMA engine : compilation YAML, evaluation et import en base."""

from __future__ import annotations

from datetime import datetime, timezone

import pytest


pytestmark = pytest.mark.integration


SAMPLE_YAML = """
title: Test Brute Force
id: 11111111-2222-3333-4444-555555555555
description: Test brute force detection
status: experimental
author: tests
level: high
logsource:
  category: authentication
detection:
  selection:
    event_type: auth.fail
  condition: selection
""".strip()


def _make_event(event_type: str = "auth.fail", **kwargs):
    from apps.api.models.event import Event

    base = dict(
        ts=datetime.now(timezone.utc),
        source="test",
        event_type=event_type,
        severity="medium",
        src_ip="10.0.0.1",
        username="alice",
        message="failed login",
        raw="{}",
    )
    base.update(kwargs)
    return Event(**base)


def test_compile_sigma_basic():
    from apps.api.detection.sigma_engine import compile_sigma

    compiled = compile_sigma(SAMPLE_YAML)

    assert compiled["title"] == "Test Brute Force"
    assert compiled["level"] == "high"
    assert "auth.fail" in compiled["event_types"]
    assert any(c["type"] == "match" for c in compiled["conditions"])


def test_compile_sigma_invalid_yaml_raises():
    from apps.api.detection.sigma_engine import compile_sigma

    with pytest.raises(ValueError):
        compile_sigma(":\n::\n  invalid")


def test_evaluate_sigma_matches_auth_fail():
    from apps.api.detection.sigma_engine import compile_sigma, evaluate_sigma_rule

    compiled = compile_sigma(SAMPLE_YAML)
    event = _make_event(event_type="auth.fail")

    assert evaluate_sigma_rule(compiled, event) is True


def test_evaluate_sigma_skips_non_matching_event_type():
    from apps.api.detection.sigma_engine import compile_sigma, evaluate_sigma_rule

    compiled = compile_sigma(SAMPLE_YAML)
    event = _make_event(event_type="web.access")

    assert evaluate_sigma_rule(compiled, event) is False


def test_import_sigma_persists_rule(db_session):
    from apps.api.detection.sigma_engine import import_sigma_rule
    from apps.api.models.sigma_rule import SigmaRule

    rule = import_sigma_rule(SAMPLE_YAML, db_session)

    assert rule.id is not None
    assert rule.enabled is True

    fetched = db_session.query(SigmaRule).filter(SigmaRule.id == rule.id).first()
    assert fetched is not None
    assert fetched.name == "Test Brute Force"


def test_get_enabled_sigma_rules_excludes_disabled(db_session):
    from apps.api.detection.sigma_engine import (
        get_enabled_sigma_rules,
        import_sigma_rule,
    )

    rule = import_sigma_rule(SAMPLE_YAML, db_session)
    rule.enabled = False
    db_session.commit()

    rules = get_enabled_sigma_rules(db_session)
    assert all(r.id != rule.id for r, _ in rules)


def test_seed_builtin_sigma_idempotent(db_session):
    from apps.api.detection.sigma_builtin import (
        BUILTIN_SIGMA_RULES,
        seed_builtin_sigma,
    )

    first = seed_builtin_sigma(db_session)
    assert first == len(BUILTIN_SIGMA_RULES)

    # Idempotent : deuxieme appel cree zero regles supplementaires.
    second = seed_builtin_sigma(db_session)
    assert second == 0
