"""Tests : helpers du sync engine phishing GoPhish (V4.6).

On cible les fonctions pures (parsing timestamps tronques, coercion details,
extraction browser) pour ne pas dependre de la DB.
"""

from __future__ import annotations

from datetime import UTC, datetime

from apps.api.pentest.phishing.sync import (
    EVENT_TYPE_MAP,
    _coerce_details,
    _extract_browser_info,
    _parse_ts,
)


def test_event_type_map_covers_gophish_messages() -> None:
    assert EVENT_TYPE_MAP["Email Sent"] == "email_sent"
    assert EVENT_TYPE_MAP["Email Opened"] == "email_opened"
    assert EVENT_TYPE_MAP["Clicked Link"] == "clicked_link"
    assert EVENT_TYPE_MAP["Submitted Data"] == "submitted_data"
    assert EVENT_TYPE_MAP["Error Sending Email"] == "email_failed"


def test_parse_ts_handles_nanoseconds_with_tz() -> None:
    # GoPhish renvoie du ns + "Z"
    ts = _parse_ts("2026-04-18T10:00:00.123456789Z")
    assert ts.year == 2026 and ts.month == 4 and ts.day == 18
    assert ts.tzinfo is not None


def test_parse_ts_handles_nanoseconds_with_explicit_offset() -> None:
    ts = _parse_ts("2026-04-18T10:00:00.123456789+02:00")
    assert ts.tzinfo is not None
    assert ts.hour == 10


def test_parse_ts_handles_no_fraction() -> None:
    ts = _parse_ts("2026-04-18T10:00:00Z")
    assert ts.tzinfo is not None


def test_parse_ts_falls_back_on_garbage() -> None:
    before = datetime.now(UTC)
    ts = _parse_ts("not-a-date")
    after = datetime.now(UTC)
    assert before <= ts <= after


def test_parse_ts_empty_returns_now() -> None:
    before = datetime.now(UTC)
    ts = _parse_ts(None)
    after = datetime.now(UTC)
    assert before <= ts <= after


def test_coerce_details_dict_passthrough() -> None:
    assert _coerce_details({"a": 1}) == {"a": 1}


def test_coerce_details_json_string() -> None:
    assert _coerce_details('{"a": 1}') == {"a": 1}


def test_coerce_details_bare_string_wrapped() -> None:
    assert _coerce_details("hello") == {"raw": "hello"}


def test_coerce_details_non_dict_json_wrapped() -> None:
    assert _coerce_details("[1, 2]") == {"raw": [1, 2]}


def test_coerce_details_none_returns_empty() -> None:
    assert _coerce_details(None) == {}


def test_extract_browser_info_ok() -> None:
    ip, ua = _extract_browser_info({"browser": {"address": "1.2.3.4", "user-agent": "curl/8"}})
    assert ip == "1.2.3.4"
    assert ua == "curl/8"


def test_extract_browser_info_missing() -> None:
    assert _extract_browser_info({}) == ("", "")
    assert _extract_browser_info({"browser": None}) == ("", "")
    assert _extract_browser_info({"browser": "not-a-dict"}) == ("", "")
