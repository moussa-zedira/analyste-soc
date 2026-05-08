"""Tests unitaires : helpers Case Management (sans DB)."""

from __future__ import annotations

from datetime import UTC, datetime

from apps.api.cases.service import (
    ALLOWED_TRANSITIONS,
    VALID_PRIORITIES,
    VALID_RESOLUTIONS,
    VALID_STATUSES,
    _custody_link,
)


def test_state_machine_terminates_at_closed():
    # Depuis "closed", aucune transition autorisee
    assert ALLOWED_TRANSITIONS["closed"] == set()


def test_state_machine_open_can_only_triage_or_close():
    assert ALLOWED_TRANSITIONS["open"] == {"triaging", "closed"}


def test_all_statuses_have_transitions_defined():
    for s in VALID_STATUSES:
        assert s in ALLOWED_TRANSITIONS


def test_priorities_and_resolutions_are_non_empty():
    assert len(VALID_PRIORITIES) >= 4
    assert len(VALID_RESOLUTIONS) >= 4


def test_custody_link_chains_via_prev_hash():
    ts1 = datetime(2026, 4, 17, 10, 0, 0, tzinfo=UTC)
    link1 = _custody_link(prev_hash="", actor="alice", action="collected", ts=ts1)
    ts2 = datetime(2026, 4, 17, 10, 5, 0, tzinfo=UTC)
    link2 = _custody_link(prev_hash=link1["hash"], actor="bob", action="copied", ts=ts2)

    assert link1["actor"] == "alice"
    assert link1["prev_hash"] == ""
    assert len(link1["hash"]) == 64  # SHA-256 hex
    assert link2["prev_hash"] == link1["hash"]
    assert link2["hash"] != link1["hash"]
