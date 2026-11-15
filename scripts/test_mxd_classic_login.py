"""Negative controls for the public redacted A22 witness."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_mxd_classic_login import CORPUS, digest, verify_public


class WitnessTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / "corpus"
        shutil.copytree(CORPUS, self.corpus)

    def _rewrite_witness(self, change: str) -> None:
        path = self.corpus / "redacted-witness.json"
        record = json.loads(path.read_text())
        if change == "status":
            record["decoded_public"]["reply_status"] = 0
        elif change == "length":
            record["private_replay"]["wire_field106_length"] = 48
        path.write_text(json.dumps(record, indent=2) + "\n")
        checks = self.corpus / "SHA256SUMS"
        checks.write_text(
            "\n".join(
                f"{digest((self.corpus / line.split('  ', 1)[1]).read_bytes())}  {line.split('  ', 1)[1]}"
                for line in checks.read_text().splitlines()
            )
            + "\n"
        )

    def test_public_explicitly_lacks_raw_proof(self) -> None:
        result = verify_public(self.corpus)
        self.assertEqual(result["status"], "metadata-only")
        self.assertEqual(result["raw_packet_proof"], "unavailable")

    def test_changed_checksum_fails(self) -> None:
        (self.corpus / "actions-redacted.txt").write_text("changed\n")
        with self.assertRaises(AssertionError):
            verify_public(self.corpus)

    def test_success_relabel_fails_after_checksum_refresh(self) -> None:
        self._rewrite_witness("status")
        with self.assertRaises(AssertionError):
            verify_public(self.corpus)

    def test_wrong_password_length_fails_after_checksum_refresh(self) -> None:
        self._rewrite_witness("length")
        with self.assertRaises(AssertionError):
            verify_public(self.corpus)


if __name__ == "__main__":
    unittest.main()
