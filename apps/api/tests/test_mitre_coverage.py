"""Tests MITRE coverage : module + endpoints REST."""

from __future__ import annotations

import pytest

pytestmark = pytest.mark.integration


def test_mitre_techniques_have_required_fields():
    from apps.api.detection.mitre import ALL_TECHNIQUES

    for t in ALL_TECHNIQUES:
        assert t.id.startswith("T")
        assert t.tactic_id.startswith("TA")
        assert t.tactic_name
        assert t.url.startswith("https://attack.mitre.org/techniques/")


def test_rule_mitre_map_uses_known_techniques():
    from apps.api.detection.mitre import RULE_MITRE_MAP, TECHNIQUES_BY_ID

    for rule_id, techs in RULE_MITRE_MAP.items():
        assert techs, f"rule {rule_id} has empty mapping"
        for tech in techs:
            assert tech.id in TECHNIQUES_BY_ID


def test_coverage_by_tactic_returns_full_matrix():
    from apps.api.detection.mitre import TACTIC_ORDER, coverage_by_tactic

    cov = coverage_by_tactic()
    for tactic in TACTIC_ORDER:
        assert tactic["id"] in cov
        assert "techniques" in cov[tactic["id"]]


def test_navigator_layer_v45_compatible():
    from apps.api.detection.mitre import navigator_layer

    layer = navigator_layer()
    assert layer["domain"] == "enterprise-attack"
    assert layer["versions"]["layer"] == "4.5"
    assert isinstance(layer["techniques"], list)
    assert layer["techniques"], "expected at least one mapped technique"
    for t in layer["techniques"]:
        assert "techniqueID" in t
        assert "score" in t
        assert 0 <= t["score"] <= 100


def test_endpoint_coverage_returns_tactics(api_client, auth_headers):
    resp = api_client.get("/detection/mitre/coverage", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert "tactics" in body
    assert "totals" in body
    assert body["totals"]["techniques_covered"] > 0


def test_endpoint_navigator_returns_v45_layer(api_client, auth_headers):
    resp = api_client.get("/detection/mitre/navigator", headers=auth_headers)
    assert resp.status_code == 200
    body = resp.json()
    assert body["versions"]["layer"] == "4.5"
    assert body["domain"] == "enterprise-attack"
    assert isinstance(body["techniques"], list)


def test_endpoint_coverage_requires_api_key(api_client):
    # Drop api key header to confirm enforcement
    headers = {k: v for k, v in api_client.headers.items() if k.lower() != "x-api-key"}
    resp = api_client.get("/detection/mitre/coverage", headers={**headers})
    # require_api_key returns 401 without the key
    assert resp.status_code in (401, 403)
