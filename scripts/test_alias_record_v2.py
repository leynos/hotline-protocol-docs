"""Structural and identity controls for retained Alias Record v2 payloads."""

import hashlib
import json
import struct
import unittest
from pathlib import Path

from alias_record_v2 import compare_recorded, decode

FIXTURES = json.loads(
    (Path(__file__).parent / "fixtures/alias-record-v2-controls.json").read_text()
)["records"]


def payload(index: int = 0) -> bytes:
    return bytes.fromhex(FIXTURES[index]["payload_hex"])


def mutate(index: int, value: bytes, base: bytes | None = None) -> bytes:
    result = bytearray(base if base is not None else payload())
    result[index : index + len(value)] = value
    return bytes(result)


class AliasRecordV2Tests(unittest.TestCase):
    def test_three_retained_controls_and_recorded_identity(self) -> None:
        self.assertEqual(len(FIXTURES), 3)
        for fixture in FIXTURES:
            with self.subTest(catalog=fixture["catalog"]):
                raw = bytes.fromhex(fixture["payload_hex"])
                self.assertEqual(
                    hashlib.sha256(raw).hexdigest(), fixture["payload_sha256"]
                )
                parsed = decode(raw)
                expected = fixture["expected"]
                self.assertEqual(parsed["identity_scope"], "recorded identity only")
                self.assertEqual(parsed["kind"], expected["kind"])
                self.assertEqual(parsed["parent_cnid"], expected["parent_cnid"])
                self.assertEqual(parsed["target_cnid"], expected["target_cnid"])
                self.assertEqual(parsed["volume_hex"], expected["volume_hex"])
                self.assertEqual(parsed["name_hex"], expected["name_hex"])
                self.assertEqual(parsed["path_hex"], expected["path_hex"])
                self.assertEqual(
                    compare_recorded(
                        parsed,
                        bytes.fromhex(expected["volume_hex"]),
                        bytes.fromhex(expected["name_hex"]),
                        bytes.fromhex(expected["path_hex"]),
                    ),
                    parsed,
                )

    def test_header_and_pascal_bounds_reject(self) -> None:
        faults = (
            b"\0" * 149,
            mutate(4, b"\0\0"),
            mutate(6, b"\0\3"),
            mutate(8, b"\0\2"),
            mutate(10, b"\x1c"),
            mutate(50, b"\x40"),
        )
        for bad in faults:
            with self.subTest(fault=bad[:12].hex()), self.assertRaises(ValueError):
                decode(bad)

    def test_tlv_bounds_tags_duplicates_pad_and_terminator_reject(self) -> None:
        raw = payload()
        # The first tag starts at the fixed 150-byte header; tag 2 is at 184.
        faults = (
            mutate(150, b"\0\x03"),  # unsupported tag
            mutate(150, b"\0\x02"),  # duplicate tag 2
            mutate(152, b"\xff\xff"),  # length beyond record
            mutate(len(raw) - 4, b"\0\x03"),  # missing terminator
            mutate(len(raw) - 2, b"\0\1"),  # nonzero terminator length
            raw + b"\0",  # trailing byte and size mismatch
        )
        for bad in faults:
            with self.subTest(fault=bad[150:156].hex()), self.assertRaises(ValueError):
                decode(bad)
        # Record 11445 has a 43-byte tag-2 value and one even-alignment pad.
        odd = payload(1)
        tag2 = odd.find(b"\0\x02\0+", 150)
        self.assertGreaterEqual(tag2, 150)
        pad = tag2 + 4 + 43
        self.assertEqual(odd[pad], 0)
        with self.assertRaises(ValueError):
            decode(mutate(pad, b"\x01", odd))
        # Create a duplicate tag after the old terminator with a corrected size.
        extra = bytearray(raw[:-4] + b"\0\x02\0\0" + raw[-4:])
        struct.pack_into(">H", extra, 4, len(extra))
        with self.assertRaises(ValueError):
            decode(bytes(extra))

    def test_expected_identity_mismatch_fails_closed(self) -> None:
        parsed = decode(payload())
        for volume, name, path in (
            (b"", b"file", b"System 9:Hotline19:Files:mothra-alias20:file"),
            (b"Unix", b"file", b"System 9:Hotline19:Files:mothra-alias20:file"),
            (b"System 9", b"other", b"System 9:Hotline19:Files:mothra-alias20:file"),
            (b"System 9", b"file", b"System 9:other:file"),
        ):
            with self.subTest(name=name), self.assertRaises(ValueError):
                compare_recorded(parsed, volume, name, path)
        original = payload()
        without_path = bytearray(original[:184] + original[232:])
        struct.pack_into(">H", without_path, 4, len(without_path))
        decoded = decode(bytes(without_path))
        self.assertIsNone(decoded["path_hex"])
        with self.assertRaisesRegex(ValueError, "Carbon path"):
            compare_recorded(
                decoded,
                b"System 9",
                b"file",
                b"System 9:Hotline19:Files:mothra-alias20:file",
            )


if __name__ == "__main__":
    unittest.main()
