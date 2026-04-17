"""Tests : shellcode encoder (XOR, alphanumeric, NOP sled, bad-byte search)."""

from __future__ import annotations

from apps.api.pentest.exploitation.shellcode_encoder import (
    alphanumeric_decode,
    alphanumeric_encode,
    find_bad_byte_positions,
    find_safe_xor_key,
    generate_nop_sled,
    rot13_bytes,
    xor_multi,
    xor_single,
    _parse_bad_bytes,
)


SAMPLE_SC = bytes.fromhex("31c050682f2f7368682f62696e89e3505389e1b00bcd80")


def test_xor_single_roundtrip():
    encoded = xor_single(SAMPLE_SC, 0xAA)
    assert encoded != SAMPLE_SC
    assert xor_single(encoded, 0xAA) == SAMPLE_SC


def test_xor_multi_roundtrip():
    key = b"\xde\xad\xbe\xef"
    encoded = xor_multi(SAMPLE_SC, key)
    assert encoded != SAMPLE_SC
    assert xor_multi(encoded, key) == SAMPLE_SC


def test_find_safe_xor_key_avoids_bad_bytes():
    bad = {0x00, 0x0A, 0x0D}
    k = find_safe_xor_key(SAMPLE_SC, bad)
    assert k is not None
    assert k not in bad
    encoded = xor_single(SAMPLE_SC, k)
    assert not any(b in bad for b in encoded)


def test_find_safe_xor_key_returns_none_when_impossible():
    # Bad-bytes = toute la plage -> impossible
    all_bytes = set(range(256))
    assert find_safe_xor_key(SAMPLE_SC, all_bytes) is None


def test_alphanumeric_roundtrip():
    encoded = alphanumeric_encode(SAMPLE_SC)
    assert all(0x41 <= b <= 0x50 for b in encoded)  # [A-P]
    assert alphanumeric_decode(encoded) == SAMPLE_SC


def test_alphanumeric_doubles_size():
    assert len(alphanumeric_encode(SAMPLE_SC)) == 2 * len(SAMPLE_SC)


def test_rot13_only_affects_letters():
    data = b"Hello123!"
    out = rot13_bytes(data)
    assert out == b"Uryyb123!"
    # Roundtrip
    assert rot13_bytes(out) == data


def test_nop_sled_x86_is_all_0x90():
    sled = generate_nop_sled(32, "x86")
    assert len(sled) == 32
    assert all(b == 0x90 for b in sled)


def test_nop_sled_arm64_has_correct_length():
    sled = generate_nop_sled(16, "arm64")
    assert len(sled) == 16


def test_bad_byte_positions_finds_them():
    data = b"\x90\x00\x90\x0a\x90"
    positions = find_bad_byte_positions(data, {0x00, 0x0A})
    assert positions == [
        {"offset": 1, "byte": 0x00},
        {"offset": 3, "byte": 0x0A},
    ]


def test_parse_bad_bytes_accepts_string_csv():
    assert _parse_bad_bytes("00,0a,0d") == {0x00, 0x0A, 0x0D}


def test_parse_bad_bytes_accepts_int_list():
    assert _parse_bad_bytes([0, 10, 13]) == {0, 10, 13}


def test_parse_bad_bytes_accepts_string_list_with_x_prefix():
    # The user passes the literal 4-char string '\x00', not a null byte.
    assert _parse_bad_bytes(["\\x00", "\\x0d"]) == {0, 13}


def test_parse_bad_bytes_none_returns_empty():
    assert _parse_bad_bytes(None) == set()
