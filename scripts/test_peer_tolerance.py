"""Adversarial checks for the frozen full-process peer evidence."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_peer_tolerance import verify

ROOT = Path(__file__).resolve().parents[2] / "mothra"
SOURCE = ROOT / "evidence/gap-remediation/2026-11-13"
CORPUS = SOURCE / "delegated-peer-01"


def changed_copy(tmp_path: Path) -> Path:
    target = tmp_path / "corpus"
    shutil.copytree(CORPUS, target)
    return target


def rewrite_sums(corpus: Path) -> None:
    prefix = CORPUS.relative_to(ROOT)
    (corpus / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {prefix / path.relative_to(corpus)}\n"
            for path in sorted(corpus.rglob("*"))
            if path.is_file() and path.name != "SHA256SUMS"
        )
    )


class PeerToleranceEvidenceTests(unittest.TestCase):
    def test_frozen_matrix_verifies(self) -> None:
        result = verify(CORPUS, SOURCE)
        self.assertEqual(result["status"], "verified")
        self.assertEqual(
            [row["case"] for row in result["cases"]],
            ["control", "omit-161", "vary-161", "unknown-login", "early-122"],
        )

    def test_wrong_peer_identity_rejected_with_fresh_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = changed_copy(Path(temporary))
            path = corpus / "manifest.json"
            manifest = json.loads(path.read_text())
            manifest["peer_binary_sha256"] = "0" * 64
            path.write_text(json.dumps(manifest))
            rewrite_sums(corpus)
            with self.assertRaisesRegex(ValueError, "identity"):
                verify(corpus, SOURCE)

    def test_wrong_login_field_rejected_with_fresh_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = changed_copy(Path(temporary))
            path = corpus / "fixtures/vary-161/report.json"
            report = json.loads(path.read_text())
            send = next(event for event in report["events"] if event["event"] == "send")
            self.assertIn("00a100020001", send["hex"])
            send["hex"] = send["hex"].replace("00a100020001", "00a100020002", 1)
            path.write_text(json.dumps(report))
            rewrite_sums(corpus)
            with self.assertRaisesRegex(ValueError, "Fixture bytes"):
                verify(corpus, SOURCE)

    def test_wrong_banner_order_rejected_with_fresh_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = changed_copy(Path(temporary))
            path = corpus / "fixtures/early-122/report.json"
            report = json.loads(path.read_text())
            sends = [event for event in report["events"] if event["event"] == "send"]
            self.assertGreaterEqual(len(sends), 3)
            sends[1]["hex"], sends[2]["hex"] = sends[2]["hex"], sends[1]["hex"]
            path.write_text(json.dumps(report))
            rewrite_sums(corpus)
            with self.assertRaisesRegex(ValueError, "Fixture bytes"):
                verify(corpus, SOURCE)
