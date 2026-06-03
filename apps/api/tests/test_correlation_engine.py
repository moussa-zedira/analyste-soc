"""Tests moteur de correlation : threshold + temporal multi-events."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

pytestmark = pytest.mark.integration


def _evt(ts, **kwargs):
    from apps.api.models.event import Event

    base = {
        "ts": ts,
        "source": "test",
        "event_type": "auth.fail",
        "severity": "medium",
        "src_ip": "10.0.0.1",
        "username": "alice",
        "message": "failed",
        "raw": "{}",
    }
    base.update(kwargs)
    return Event(**base)


def test_threshold_correlation_fires_above_threshold():
    from apps.api.detection.correlation import (
        CorrelationEngine,
        CorrelationRule,
        CorrelationType,
        EventPattern,
    )

    engine = CorrelationEngine()
    rule = CorrelationRule(
        id="test-threshold",
        name="Burst auth fails",
        description="5 fails / 60s",
        correlation_type=CorrelationType.THRESHOLD,
        event_patterns=[EventPattern(event_type="auth.fail")],
        time_window=60,
        group_by=["src_ip"],
        threshold=5,
        severity="high",
        mitre_tactics=["credential-access"],
    )
    engine.register_rule(rule)

    base_ts = datetime.now(UTC)
    events = [_evt(base_ts + timedelta(seconds=i * 5)) for i in range(6)]

    matches = engine.evaluate(events)
    assert len(matches) == 1
    m = matches[0]
    assert m.rule_id == "test-threshold"
    assert m.severity == "high"
    assert "credential-access" in m.mitre_tactics


def test_threshold_correlation_below_threshold_no_match():
    from apps.api.detection.correlation import (
        CorrelationEngine,
        CorrelationRule,
        CorrelationType,
        EventPattern,
    )

    engine = CorrelationEngine()
    engine.register_rule(
        CorrelationRule(
            id="test-low",
            name="Burst",
            description="5 in 60s",
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[EventPattern(event_type="auth.fail")],
            time_window=60,
            group_by=["src_ip"],
            threshold=5,
        )
    )

    base_ts = datetime.now(UTC)
    events = [_evt(base_ts + timedelta(seconds=i * 5)) for i in range(3)]

    assert engine.evaluate(events) == []


def test_threshold_correlation_groups_by_src_ip():
    from apps.api.detection.correlation import (
        CorrelationEngine,
        CorrelationRule,
        CorrelationType,
        EventPattern,
    )

    engine = CorrelationEngine()
    engine.register_rule(
        CorrelationRule(
            id="grp",
            name="Per-IP burst",
            description="3 fails per IP / 60s",
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[EventPattern(event_type="auth.fail")],
            time_window=60,
            group_by=["src_ip"],
            threshold=3,
        )
    )

    base = datetime.now(UTC)
    events = [
        _evt(base + timedelta(seconds=1), src_ip="10.0.0.1"),
        _evt(base + timedelta(seconds=2), src_ip="10.0.0.1"),
        _evt(base + timedelta(seconds=3), src_ip="10.0.0.1"),
        _evt(base + timedelta(seconds=4), src_ip="10.0.0.2"),
    ]

    matches = engine.evaluate(events)
    assert len(matches) == 1
    assert "10.0.0.1" in matches[0].group_key


def test_temporal_correlation_two_patterns():
    from apps.api.detection.correlation import (
        CorrelationEngine,
        CorrelationRule,
        CorrelationType,
        EventPattern,
    )

    engine = CorrelationEngine()
    engine.register_rule(
        CorrelationRule(
            id="temporal-test",
            name="Fail then success",
            description="auth.fail then auth.success same IP within 60s",
            correlation_type=CorrelationType.TEMPORAL,
            event_patterns=[
                EventPattern(event_type="auth.fail", label="fail"),
                EventPattern(event_type="auth.success", label="success"),
            ],
            time_window=60,
            group_by=["src_ip"],
        )
    )

    base = datetime.now(UTC)
    events = [
        _evt(base, event_type="auth.fail"),
        _evt(base + timedelta(seconds=5), event_type="auth.success"),
    ]

    matches = engine.evaluate(events)
    assert len(matches) >= 1


def test_evaluate_dedup_per_rule_and_group():
    from apps.api.detection.correlation import (
        CorrelationEngine,
        CorrelationRule,
        CorrelationType,
        EventPattern,
    )

    engine = CorrelationEngine()
    engine.register_rule(
        CorrelationRule(
            id="dedup",
            name="dedup",
            description="",
            correlation_type=CorrelationType.THRESHOLD,
            event_patterns=[EventPattern(event_type="auth.fail")],
            time_window=60,
            group_by=["src_ip"],
            threshold=3,
        )
    )

    base = datetime.now(UTC)
    events = [_evt(base + timedelta(seconds=i)) for i in range(10)]

    matches = engine.evaluate(events)
    keys = {f"{m.rule_id}|{m.group_key}" for m in matches}
    assert len(matches) == len(keys)  # no duplicates
