"""Tests unitaires : compliance reporter (sans DB)."""

from __future__ import annotations

from apps.api.compliance.frameworks import (
    ALL_FRAMEWORKS,
    NIS2,
    Control,
    Framework,
    list_frameworks,
)
from apps.api.compliance.reporter import (
    evaluate_all,
    evaluate_control,
    evaluate_framework,
)


def test_all_frameworks_loaded():
    ids = {f["id"] for f in list_frameworks()}
    assert ids == {"nis2", "dora", "pci-dss", "iso-27001", "nist-csf"}


def test_evaluate_control_covered_when_static_evidence_exists():
    ctrl = Control(
        id="t.1",
        title="Test cov",
        description="",
        capabilities=["sigma.rules"],
    )
    res = evaluate_control(ctrl, db=None)
    assert res["status"] == "covered"
    assert "sigma.rules" in res["covered_capabilities"]
    assert res["evidence"]["sigma.rules"]


def test_evaluate_control_uncovered_when_unknown_capability():
    ctrl = Control(
        id="t.2",
        title="Test unc",
        description="",
        capabilities=["does.not.exist"],
    )
    res = evaluate_control(ctrl, db=None)
    assert res["status"] == "uncovered"
    assert res["missing_capabilities"] == ["does.not.exist"]


def test_evaluate_control_partial_when_some_caps_missing():
    ctrl = Control(
        id="t.3",
        title="Test part",
        description="",
        capabilities=["sigma.rules", "does.not.exist"],
    )
    res = evaluate_control(ctrl, db=None)
    assert res["status"] == "partial"
    assert "sigma.rules" in res["covered_capabilities"]
    assert "does.not.exist" in res["missing_capabilities"]


def test_evaluate_control_manual_when_no_capabilities():
    ctrl = Control(id="t.4", title="Manual only", description="", capabilities=[])
    res = evaluate_control(ctrl, db=None)
    assert res["status"] == "manual"


def test_evaluate_framework_aggregates_correctly():
    rep = evaluate_framework(NIS2, db=None)
    assert rep["framework"]["id"] == "nis2"
    assert rep["summary"]["controls_total"] == len(NIS2.controls)
    counts = rep["summary"]["by_status"]
    assert sum(counts.values()) == rep["summary"]["controls_total"]
    assert 0.0 <= rep["summary"]["coverage_score"] <= 100.0


def test_evaluate_all_returns_one_entry_per_framework():
    reports = evaluate_all(db=None)
    assert set(reports.keys()) == set(ALL_FRAMEWORKS.keys())
    for fid, rep in reports.items():
        assert rep["framework"]["id"] == fid
