"""Semantic fault controls for the retained D1 console broadcast."""

import hashlib
import json
import os
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_console_broadcast import verify

SOURCE = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-console-broadcast-01"
)


class NativeConsoleBroadcastTests(unittest.TestCase):
    def setUp(self) -> None:
        state = SOURCE.parents[3] / "state"
        state.mkdir(exist_ok=True)
        self.temp = tempfile.TemporaryDirectory(dir=state)
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "corpus"
        shutil.copytree(SOURCE, self.root, copy_function=os.link)

    def replace(self, name: str, raw: bytes) -> None:
        target = self.root / name
        target.unlink()
        target.write_bytes(raw)
        manifest = json.loads((self.root / "manifest.json").read_text())
        manifest["files"][name] = hashlib.sha256(raw).hexdigest()
        (self.root / "manifest.json").unlink()
        (self.root / "manifest.json").write_text(json.dumps(manifest))

    def test_original(self) -> None:
        result = verify(self.root)
        self.assertEqual(result["status"], "verified-finite-native-console-broadcast")
        self.assertEqual(result["postflight"]["files_root"], 41)

    def test_guest_message_byte_changed_after_manifest_rehash(self) -> None:
        name = "guest-after.pcap"
        raw = (self.root / name).read_bytes()
        self.assertIn(b"D1-console-message", raw)
        self.replace(name, raw.replace(b"D1-console-message", b"D1-console-messagf", 1))
        with self.assertRaisesRegex(ValueError, "Guest/report bytes differ"):
            verify(self.root)

    def test_host_recipient_syn_missing_after_manifest_rehash(self) -> None:
        name = "host.pcap"
        raw = (self.root / name).read_bytes()
        at = 24
        kept = bytearray(raw[:24])
        removed = 0
        while at < len(raw):
            size = int.from_bytes(raw[at + 8 : at + 12], "little")
            record = raw[at : at + 16 + size]
            frame = record[16:]
            # The refused peer's one SYN, 127.0.0.1:53796 -> 15500.
            if (
                frame[12:14] == b"\x08\x00"
                and frame[34:38] == bytes.fromhex("d2243c8c")
                and frame[47] == 2
            ):
                removed += 1
            else:
                kept.extend(record)
            at += 16 + size
        self.assertEqual(removed, 1)
        self.replace(name, bytes(kept))
        with self.assertRaisesRegex(ValueError, "Host missing-SYN scope differs"):
            verify(self.root)

    def test_operator_two_sends_rejected_after_manifest_rehash(self) -> None:
        name = "operator-actions.json"
        actions = json.loads((self.root / name).read_text())
        actions["result"] = "Two console sends"
        self.replace(name, json.dumps(actions).encode())
        with self.assertRaisesRegex(ValueError, "Operator scope differs"):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
