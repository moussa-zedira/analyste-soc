"""Tests unitaires : UBA scoring (sans DB) sur _surprise et _entity_key."""

from __future__ import annotations

from datetime import UTC, datetime
from types import SimpleNamespace

from apps.api.uba.engine import _entity_key, _hour_bucket, _surprise, _ua_hash


def test_surprise_high_for_rare_event():
    # 1 observation sur 1000 events, 50 buckets distincts -> tres rare
    s_rare = _surprise(observed=0, total=1000, distinct_buckets=50)
    s_common = _surprise(observed=500, total=1000, distinct_buckets=50)
    assert s_rare > s_common
    assert s_rare > 5.0  # ≥ 5 bits = improbable
    assert s_common < 2.0


def test_surprise_zero_obs_still_finite():
    # Aucune observation, zero total -> doit pas crasher (Laplace smoothing)
    s = _surprise(observed=0, total=0, distinct_buckets=0)
    assert s >= 0.0


def test_entity_key_priority_user_first():
    ev = SimpleNamespace(raw={"user": "alice"}, src_ip="10.0.0.1", host="host1")
    assert _entity_key(ev) == ("user", "alice")


def test_entity_key_falls_back_to_ip():
    ev = SimpleNamespace(raw={}, src_ip="10.0.0.1", host="host1")
    assert _entity_key(ev) == ("ip", "10.0.0.1")


def test_entity_key_falls_back_to_host():
    ev = SimpleNamespace(raw={}, src_ip=None, host="host1")
    assert _entity_key(ev) == ("host", "host1")


def test_entity_key_returns_none_when_no_signal():
    ev = SimpleNamespace(raw={}, src_ip=None, host=None)
    assert _entity_key(ev) is None


def test_ua_hash_is_deterministic_and_short():
    h1 = _ua_hash("Mozilla/5.0")
    h2 = _ua_hash("Mozilla/5.0")
    assert h1 == h2
    assert len(h1) == 12


def test_hour_bucket_returns_string_in_range():
    ts = datetime(2026, 4, 17, 14, 30, tzinfo=UTC)
    assert _hour_bucket(ts) == "14"
