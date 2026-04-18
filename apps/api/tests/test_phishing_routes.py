"""Tests d'integration: routes /redteam/phishing (V4.6b).

Couvre :
- creation avec engagement: scope check par domaine email
- creation bloquee par kill-switch (423)
- creation bloquee par status != active (409)
- endpoint stop (bascule status=stopped + audit)
- sync engine: dedup + recompte counts + kill-switch propagation
"""

from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone

import pytest

pytestmark = pytest.mark.integration


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_engagement(
    db_session,
    *,
    status: str = "active",
    scope: list[str] | None = None,
    excluded: list[str] | None = None,
    kill_switch: bool = False,
    start_at: datetime | None = None,
    end_at: datetime | None = None,
):
    from apps.api.models.engagement import Engagement

    now = datetime.now(timezone.utc)
    eng = Engagement(
        id=f"eng-{uuid.uuid4().hex[:8]}",
        name="ACME RedTeam",
        client_name="ACME",
        status=status,
        scope_targets=scope or ["acme.com"],
        excluded_targets=excluded or [],
        start_date=start_at,
        end_date=end_at,
        kill_switch_active=kill_switch,
        created_by=None,
        created_at=now,
        notes="",
        mitre_tactics_authorized=[],
    )
    db_session.add(eng)
    db_session.commit()
    return eng


def _make_campaign(
    db_session,
    *,
    engagement_id: str | None = None,
    status: str = "sending",
    gp_id: int | None = 42,
):
    from apps.api.models.phishing import PhishingCampaign

    now = datetime.now(timezone.utc)
    c = PhishingCampaign(
        id=f"pc-{uuid.uuid4().hex[:8]}",
        name=f"C-{uuid.uuid4().hex[:4]}",
        engagement_id=engagement_id,
        gophish_campaign_id=gp_id,
        status=status,
        template_name="T",
        landing_url="https://lp.example/",
        sent_count=0,
        opened_count=0,
        clicked_count=0,
        submitted_count=0,
        email_failed_count=0,
        launched_at=now,
        completed_at=None,
        created_by=None,
        created_at=now,
        mitre_technique="T1566.001",
        notes="",
        last_synced_at=None,
    )
    db_session.add(c)
    db_session.commit()
    return c


def _register_gophish_env(monkeypatch):
    """Les env vars doivent etre presentes pour que _gophish_or_503 passe."""
    import os

    monkeypatch.setenv("GOPHISH_API_URL", "https://gp.test")
    monkeypatch.setenv("GOPHISH_API_KEY", "test-key")
    # Invalide le cache Settings pour que le lru_cache relise l'env.
    from apps.api.config import get_settings

    get_settings.cache_clear()
    yield_settings = get_settings()
    assert yield_settings.GOPHISH_API_URL == "https://gp.test"


def _login_role(api_client, role: str) -> dict[str, str]:
    n = uuid.uuid4().hex[:6]
    api_client.post(
        "/auth/register",
        json={
            "username": f"u-{n}",
            "email": f"u-{n}@t.local",
            "password": "Pwd-" + n,
            "role": role,
        },
    )
    r = api_client.post(
        "/auth/login", json={"username": f"u-{n}", "password": "Pwd-" + n}
    )
    return {"Authorization": f"Bearer {r.json()['access_token']}"}


# ---------------------------------------------------------------------------
# Scope / kill-switch guards
# ---------------------------------------------------------------------------


def test_create_campaign_blocks_when_kill_switch_active(
    api_client, db_session, monkeypatch
):
    _register_gophish_env(monkeypatch)
    eng = _make_engagement(db_session, kill_switch=True)
    headers = _login_role(api_client, "lead")

    r = api_client.post(
        "/redteam/phishing/campaigns",
        headers=headers,
        json={
            "name": "K1",
            "engagement_id": eng.id,
            "template_name": "T",
            "landing_url": "https://x.test/",
            "smtp_profile": "S",
            "targets": [
                {
                    "email": "alice@acme.com",
                    "first_name": "Alice",
                    "last_name": "",
                    "position": "",
                }
            ],
        },
    )
    assert r.status_code == 423


def test_create_campaign_blocks_when_status_not_active(
    api_client, db_session, monkeypatch
):
    _register_gophish_env(monkeypatch)
    eng = _make_engagement(db_session, status="paused")
    headers = _login_role(api_client, "lead")

    r = api_client.post(
        "/redteam/phishing/campaigns",
        headers=headers,
        json={
            "name": "P1",
            "engagement_id": eng.id,
            "template_name": "T",
            "landing_url": "https://x.test/",
            "smtp_profile": "S",
            "targets": [
                {"email": "a@acme.com", "first_name": "", "last_name": "", "position": ""}
            ],
        },
    )
    assert r.status_code == 409


def test_create_campaign_blocks_out_of_scope_emails(
    api_client, db_session, monkeypatch
):
    _register_gophish_env(monkeypatch)
    eng = _make_engagement(db_session, scope=["acme.com"])
    headers = _login_role(api_client, "lead")

    r = api_client.post(
        "/redteam/phishing/campaigns",
        headers=headers,
        json={
            "name": "S1",
            "engagement_id": eng.id,
            "template_name": "T",
            "landing_url": "https://x.test/",
            "smtp_profile": "S",
            "targets": [
                {"email": "ok@acme.com", "first_name": "", "last_name": "", "position": ""},
                {"email": "bad@evil.com", "first_name": "", "last_name": "", "position": ""},
            ],
        },
    )
    assert r.status_code == 403
    body = r.json()
    assert body["detail"]["error"] == "targets_out_of_scope"
    assert "bad@evil.com" in body["detail"]["emails"]
    assert "ok@acme.com" not in body["detail"]["emails"]


def test_create_campaign_blocks_when_before_start_date(
    api_client, db_session, monkeypatch
):
    _register_gophish_env(monkeypatch)
    future = datetime.now(timezone.utc) + timedelta(days=7)
    eng = _make_engagement(db_session, start_at=future)
    headers = _login_role(api_client, "lead")

    r = api_client.post(
        "/redteam/phishing/campaigns",
        headers=headers,
        json={
            "name": "F1",
            "engagement_id": eng.id,
            "template_name": "T",
            "landing_url": "https://x.test/",
            "smtp_profile": "S",
            "targets": [
                {"email": "a@acme.com", "first_name": "", "last_name": "", "position": ""}
            ],
        },
    )
    assert r.status_code == 412


# ---------------------------------------------------------------------------
# Stop endpoint
# ---------------------------------------------------------------------------


def test_stop_campaign_sets_status_stopped_and_audits(
    api_client, db_session, monkeypatch
):
    from apps.api.pentest.phishing import gophish_client as gc

    _register_gophish_env(monkeypatch)

    async def _fake_delete(self, gp_id):  # noqa: ARG001
        return {"success": True}

    monkeypatch.setattr(gc.GoPhishClient, "delete_campaign", _fake_delete)

    eng = _make_engagement(db_session)
    camp = _make_campaign(db_session, engagement_id=eng.id, status="sending")
    headers = _login_role(api_client, "lead")

    r = api_client.post(
        f"/redteam/phishing/campaigns/{camp.id}/stop", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["status"] == "stopped"
    assert r.json()["gophish_deleted"] is True

    db_session.expire_all()
    from apps.api.models.phishing import PhishingCampaign

    again = db_session.get(PhishingCampaign, camp.id)
    assert again.status == "stopped"
    assert again.completed_at is not None


def test_stop_campaign_noop_when_already_completed(
    api_client, db_session, monkeypatch
):
    _register_gophish_env(monkeypatch)
    eng = _make_engagement(db_session)
    camp = _make_campaign(db_session, engagement_id=eng.id, status="completed")
    headers = _login_role(api_client, "lead")

    r = api_client.post(
        f"/redteam/phishing/campaigns/{camp.id}/stop", headers=headers
    )
    assert r.status_code == 200
    assert r.json()["status"] == "noop"


# ---------------------------------------------------------------------------
# Sync engine: dedup + counts + kill-switch propagation
# ---------------------------------------------------------------------------


def test_sync_campaign_dedups_events_and_recomputes_counts(
    db_session, monkeypatch
):
    import asyncio

    from apps.api.models.phishing import (
        PhishingResult,
        PhishingTarget,
    )
    from apps.api.pentest.phishing import gophish_client as gc
    from apps.api.pentest.phishing.sync import sync_campaign

    _register_gophish_env(monkeypatch)

    eng = _make_engagement(db_session)
    camp = _make_campaign(db_session, engagement_id=eng.id, gp_id=77)
    t = PhishingTarget(
        id=f"pt-{uuid.uuid4().hex[:6]}",
        campaign_id=camp.id,
        email="alice@acme.com",
        first_name="A",
        last_name="",
        position="",
        group_name="g",
        last_status="pending",
    )
    db_session.add(t)
    db_session.commit()

    timeline = [
        {
            "email": "alice@acme.com",
            "message": "Email Sent",
            "time": "2026-04-18T10:00:00Z",
            "details": "",
        },
        {
            "email": "alice@acme.com",
            "message": "Email Opened",
            "time": "2026-04-18T10:05:00Z",
            "details": '{"browser": {"address": "1.2.3.4", "user-agent": "ua/1"}}',
        },
        {
            "email": "alice@acme.com",
            "message": "Clicked Link",
            "time": "2026-04-18T10:06:00Z",
            "details": "",
        },
    ]

    async def _fake_results(self, gp_id):  # noqa: ARG001
        return {"timeline": timeline, "results": []}

    monkeypatch.setattr(gc.GoPhishClient, "get_campaign_results", _fake_results)

    res1 = asyncio.run(sync_campaign(db_session, camp.id))
    assert res1["status"] == "ok"
    assert res1["new_events"] == 3

    # 2e sync: idempotent, 0 nouveau
    res2 = asyncio.run(sync_campaign(db_session, camp.id))
    assert res2["new_events"] == 0

    db_session.expire_all()
    from apps.api.models.phishing import PhishingCampaign

    c = db_session.get(PhishingCampaign, camp.id)
    assert c.sent_count == 1
    assert c.opened_count == 1
    assert c.clicked_count == 1
    assert c.submitted_count == 0

    events = (
        db_session.query(PhishingResult)
        .filter_by(campaign_id=camp.id)
        .all()
    )
    assert len(events) == 3
    opened = [e for e in events if e.event_type == "email_opened"][0]
    assert opened.ip_address == "1.2.3.4"
    assert opened.user_agent == "ua/1"


def test_sync_all_enforces_kill_switch(db_session, monkeypatch):
    import asyncio

    from apps.api.models.phishing import PhishingCampaign
    from apps.api.pentest.phishing import gophish_client as gc
    from apps.api.pentest.phishing.sync import sync_all_active_campaigns

    _register_gophish_env(monkeypatch)

    eng = _make_engagement(db_session, kill_switch=True)
    camp = _make_campaign(db_session, engagement_id=eng.id, status="sending")

    deleted: list[int] = []

    async def _fake_delete(self, gp_id):
        deleted.append(gp_id)
        return {"success": True}

    async def _fake_results(self, gp_id):  # noqa: ARG001
        raise AssertionError("sync should not call GoPhish when killed")

    monkeypatch.setattr(gc.GoPhishClient, "delete_campaign", _fake_delete)
    monkeypatch.setattr(gc.GoPhishClient, "get_campaign_results", _fake_results)

    res = asyncio.run(sync_all_active_campaigns(db_session))
    assert res["killed"] == 1
    assert deleted == [camp.gophish_campaign_id]

    db_session.expire_all()
    c = db_session.get(PhishingCampaign, camp.id)
    assert c.status == "stopped"
