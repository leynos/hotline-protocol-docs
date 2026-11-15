"""Fault controls for the portable synthetic Classic proxy corpus."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_classic_proxy_rehearsal import verify

SOURCE = (
    Path(__file__).resolve().parent.parent
    / "evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01"
)


class ClassicProxyRehearsalTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        base = Path(self.temp.name)
        self.root = (
            base / "evidence/gap-remediation/2026-11-13/classic-proxy-rehearsal-01"
        )
        self.root.parent.mkdir(parents=True)
        shutil.copytree(SOURCE, self.root)

    def rewrite_inventory(self) -> None:
        base = self.root.parents[3]
        files = sorted(
            path
            for path in self.root.rglob("*")
            if path.is_file() and path.name != "SHA256SUMS"
        )
        (self.root / "SHA256SUMS").write_text(
            "".join(
                f"{hashlib.sha256(path.read_bytes()).hexdigest()}  "
                f"{path.relative_to(base)}\n"
                for path in files
            )
        )

    def change_json(self, relative: str, mutate) -> None:
        path = self.root / relative
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.rewrite_inventory()

    def test_valid_synthetic_and_zero_contact_corpus(self) -> None:
        self.assertEqual(
            verify(self.root)["status"], "verified-synthetic-and-zero-contact"
        )

    def test_rejects_incorrect_native_evidence_claim(self) -> None:
        self.change_json(
            "manifest.json", lambda value: value.update(native_peer_evidence=True)
        )
        with self.assertRaises(AssertionError):
            verify(self.root)

    def test_rejects_late_teardown_even_with_stale_valid_flag(self) -> None:
        def late(value: dict) -> None:
            value["observation"]["relay_teardown_ns"] += 3_000_000_000

        self.change_json("synthetic/report.json", late)
        with self.assertRaises(AssertionError):
            verify(self.root)

    def test_rejects_reordered_handshake(self) -> None:
        def reorder(value: dict) -> None:
            value["entries"][0], value["entries"][1] = (
                value["entries"][1],
                value["entries"][0],
            )

        self.change_json("synthetic/report.json", reorder)
        with self.assertRaises(AssertionError):
            verify(self.root)

    def test_rejects_undestroyed_proxy_pid_proof(self) -> None:
        self.change_json(
            "synthetic/summary.json", lambda value: value.update(proxy_pid_gone=False)
        )
        with self.assertRaises(AssertionError):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
