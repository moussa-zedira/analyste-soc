"""Tests : K8s RBAC analyzer (wildcard verbs/resources, cluster-admin, default SA)."""

from __future__ import annotations

from apps.api.pentest.recon.k8s_rbac import (
    DANGEROUS_RESOURCES,
    DANGEROUS_VERBS,
    _find_dangerous_rules,
    audit_manifest,
)

CLUSTER_ADMIN_BIND = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: bad-binding
subjects:
- kind: ServiceAccount
  name: default
  namespace: prod
roleRef:
  kind: ClusterRole
  name: cluster-admin
  apiGroup: rbac.authorization.k8s.io
"""


WILDCARD_ROLE = """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: god-role
rules:
- apiGroups: ["*"]
  resources: ["*"]
  verbs: ["*"]
"""


SECRETS_READER = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: secrets-reader
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["secrets"]
  verbs: ["get", "list"]
"""


SAFE_ROLE = """
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: pod-reader
  namespace: dev
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
"""


SA_NO_AUTOMOUNT = """
apiVersion: v1
kind: ServiceAccount
metadata:
  name: my-sa
  namespace: prod
"""


def test_audit_detects_cluster_admin_binding():
    result = audit_manifest(CLUSTER_ADMIN_BIND)
    titles = [f["title"] for f in result["findings"]]
    assert any("cluster-admin" in t for t in titles)
    assert result["by_severity"].get("critical", 0) >= 1


def test_audit_detects_wildcard_god_role():
    result = audit_manifest(WILDCARD_ROLE)
    assert result["findings_count"] >= 1
    crit = [f for f in result["findings"] if f["severity"] == "critical"]
    assert len(crit) >= 1
    assert "cluster-admin" in crit[0]["title"]


def test_audit_flags_secrets_role_as_high():
    result = audit_manifest(SECRETS_READER)
    assert result["findings_count"] >= 1
    sevs = {f["severity"] for f in result["findings"]}
    assert "high" in sevs


def test_audit_safe_role_produces_no_findings():
    result = audit_manifest(SAFE_ROLE)
    assert result["findings_count"] == 0


def test_audit_default_sa_binding_flagged_high():
    result = audit_manifest(CLUSTER_ADMIN_BIND)
    high_or_critical = [
        f for f in result["findings"]
        if f["severity"] in ("high", "critical")
        and "default" in f["title"].lower()
    ]
    assert len(high_or_critical) >= 1


def test_audit_serviceaccount_missing_automount():
    result = audit_manifest(SA_NO_AUTOMOUNT)
    assert result["findings_count"] >= 1
    assert any("automountServiceAccountToken" in f["title"] for f in result["findings"])


def test_audit_target_principal_filter():
    text = CLUSTER_ADMIN_BIND
    full = audit_manifest(text)
    filtered = audit_manifest(text, target_principal="default")
    assert filtered["findings_count"] <= full["findings_count"]
    assert filtered["findings_count"] >= 1


def test_audit_invalid_yaml_raises():
    import pytest
    from fastapi import HTTPException
    with pytest.raises(HTTPException):
        audit_manifest(":\n  - bad: [unclosed")


def test_find_dangerous_rules_empty():
    assert _find_dangerous_rules([]) == []
    assert _find_dangerous_rules(None) == []  # type: ignore[arg-type]


def test_dangerous_constants_present():
    assert "*" in DANGEROUS_VERBS
    assert "escalate" in DANGEROUS_VERBS
    assert "secrets" in DANGEROUS_RESOURCES
    assert "pods/exec" in DANGEROUS_RESOURCES


def test_audit_resolves_role_via_binding():
    multi = WILDCARD_ROLE + "\n---\n" + """
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: god-bind
subjects:
- kind: User
  name: alice
roleRef:
  kind: ClusterRole
  name: god-role
  apiGroup: rbac.authorization.k8s.io
"""
    result = audit_manifest(multi)
    assert any(
        "god-role" in f["title"] and "alice" in f["title"]
        for f in result["findings"]
    )


def test_audit_documents_count_matches():
    result = audit_manifest(WILDCARD_ROLE + "\n---\n" + SAFE_ROLE)
    assert result["documents_parsed"] == 2
    assert result["rbac_documents"] == 2
