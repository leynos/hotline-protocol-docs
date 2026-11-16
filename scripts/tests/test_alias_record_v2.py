"""Structural and identity controls for retained Alias Record v2 payloads."""

import hashlib
import json
import struct
from pathlib import Path

import pytest
from alias_record_v2 import compare_recorded, decode

# scripts/tests sits one level below scripts/, which holds the fixtures.
FIXTURES = json.loads(
    (
        Path(__file__).parent.parent / "fixtures/alias-record-v2-controls.json"
    ).read_text()
)["records"]
PATH = b"System 9:Hotline19:Files:mothra-alias20:file"


def payload(index: int = 0) -> bytes:
    """Return one retained control payload.

    Returns
    -------
    bytes
        The payload of the fixture at ``index``.
    """
    return bytes.fromhex(FIXTURES[index]["payload_hex"])


def mutate(index: int, value: bytes, base: bytes | None = None) -> bytes:
    """Overwrite some bytes of a payload.

    Returns
    -------
    bytes
        The payload with ``value`` written at ``index``.
    """
    result = bytearray(base if base is not None else payload())
    result[index : index + len(value)] = value
    return bytes(result)


class AliasRecordV2Tests:
    """Reject each malformed or mismatched Alias Record v2 payload."""

    def test_three_retained_controls_and_recorded_identity(self) -> None:
        """Decode each retained payload to its recorded identity."""
        assert len(FIXTURES) == 3, "len(FIXTURES) == 3"
        for fixture in FIXTURES:
            raw = bytes.fromhex(fixture["payload_hex"])
            assert hashlib.sha256(raw).hexdigest() == fixture["payload_sha256"], (
                f"payload digest of catalog {fixture['catalog']}"
            )
            parsed = decode(raw)
            expected = fixture["expected"]
            assert parsed["identity_scope"] == "recorded identity only", (
                f"identity scope of catalog {fixture['catalog']}"
            )
            for key in ("kind", "parent_cnid", "target_cnid"):
                assert parsed[key] == expected[key], f"{key} of {fixture['catalog']}"
            for key in ("volume_hex", "name_hex", "path_hex"):
                assert parsed[key] == expected[key], f"{key} of {fixture['catalog']}"
            compared = compare_recorded(
                parsed,
                bytes.fromhex(expected["volume_hex"]),
                bytes.fromhex(expected["name_hex"]),
                bytes.fromhex(expected["path_hex"]),
            )
            assert compared == parsed, f"comparison of catalog {fixture['catalog']}"

    def test_header_and_pascal_bounds_reject(self) -> None:
        """Refuse a short record, a wrong size, version or kind and long names."""
        faults = (
            (b"\0" * 149, "Alias record shorter than v2 header"),
            (mutate(4, b"\0\0"), "Alias declared size differs from payload"),
            (mutate(6, b"\0\3"), "Unsupported Alias Record version"),
            (mutate(8, b"\0\2"), "Unsupported Alias Record kind"),
            (mutate(10, b"\x1c"), "Alias Pascal name exceeds fixed slot"),
            (mutate(50, b"\x40"), "Alias Pascal name exceeds fixed slot"),
        )
        for bad, message in faults:
            with pytest.raises(ValueError, match=message):
                decode(bad)

    def test_tlv_bounds_tags_duplicates_pad_and_terminator_reject(self) -> None:
        """Refuse tag, length, terminator, alignment and duplicate-tag faults."""
        raw = payload()
        # The first tag starts at the fixed 150-byte header; tag 2 is at 184.
        faults = (
            (mutate(150, b"\0\x03"), "Unsupported Alias tag"),
            (mutate(150, b"\0\x02"), "Duplicate Alias tag"),
            (mutate(152, b"\xff\xff"), "Alias tag value exceeds record"),
            (mutate(len(raw) - 4, b"\0\x03"), "Unsupported Alias tag"),
            (mutate(len(raw) - 2, b"\0\1"), "Alias terminator has a value"),
            (raw + b"\0", "Alias declared size differs from payload"),
        )
        for bad, message in faults:
            with pytest.raises(ValueError, match=message):
                decode(bad)
        # Record 11445 has a 43-byte tag-2 value and one even-alignment pad.
        odd = payload(1)
        tag2 = odd.find(b"\0\x02\0+", 150)
        assert tag2 >= 150, "tag2 >= 150"
        pad = tag2 + 4 + 43
        assert odd[pad] == 0, "odd[pad] == 0"
        with pytest.raises(ValueError, match="Invalid Alias alignment byte"):
            decode(mutate(pad, b"\x01", odd))
        # Create a duplicate tag after the old terminator with a corrected size.
        extra = bytearray(raw[:-4] + b"\0\x02\0\0" + raw[-4:])
        struct.pack_into(">H", extra, 4, len(extra))
        with pytest.raises(ValueError, match="Duplicate Alias tag"):
            decode(bytes(extra))

    def test_expected_identity_mismatch_fails_closed(self) -> None:
        """Refuse an expected identity that differs from the recorded one."""
        parsed = decode(payload())
        faults = (
            (b"", b"file", PATH, "Expected Alias identity is empty"),
            (b"Unix", b"file", PATH, "Recorded volume differs"),
            (b"System 9", b"other", PATH, "Recorded target name differs"),
            (
                b"System 9",
                b"file",
                b"System 9:other:file",
                "Recorded Carbon path absent or differs",
            ),
        )
        for volume, name, path, message in faults:
            with pytest.raises(ValueError, match=message):
                compare_recorded(parsed, volume, name, path)
        original = payload()
        without_path = bytearray(original[:184] + original[232:])
        struct.pack_into(">H", without_path, 4, len(without_path))
        decoded = decode(bytes(without_path))
        assert decoded["path_hex"] is None, 'decoded["path_hex"] is None'
        with pytest.raises(ValueError, match="Carbon path"):
            compare_recorded(decoded, b"System 9", b"file", PATH)
