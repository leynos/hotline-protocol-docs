"""Check that native fixture verification rejects semantically wrong evidence."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from protocol_capture import verify_capture
from verify_native_core import verify

FIXTURES = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-core-01"
)


class NativeCoreTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.directory = Path(temporary.name) / "fixtures"
        shutil.copytree(FIXTURES, self.directory)

    def test_retained_native_observations_verify(self) -> None:
        self.assertEqual(verify(self.directory)["transcripts"], 16)

    def test_structurally_valid_wrong_correlation_is_rejected(self) -> None:
        case = self.directory / "early-login-and-errors"
        report = json.loads((case / "report.json").read_text())
        first = report["frames"][0]
        event = next(
            e
            for e in report["events"]
            if e["action"] == first["action"] and e["event"] == "receive"
        )
        data = bytearray.fromhex(event["hex"])
        data[4:8] = bytes(4)
        event["hex"] = data.hex()
        first["id"] = 0
        report["streams"]["main"]["received_hex"] = "".join(
            e["hex"] for e in report["events"] if e["event"] == "receive"
        )
        (case / "report.json").write_text(json.dumps(report))
        (case / "checksums.sha256").write_text(
            "".join(
                f"{hashlib.sha256((case / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ["plan.json", "report.json"]
            )
        )
        verify_capture(case)
        with self.assertRaisesRegex(ValueError, "Direct reply correlation"):
            verify(self.directory)

    def test_wrong_stored_password_is_rejected(self) -> None:
        path = self.directory / "fixture-account-after-update.bin"
        data = bytearray(path.read_bytes())
        data[0x2BE] ^= 1
        path.write_bytes(data)
        with self.assertRaisesRegex(ValueError, "Stored nonempty password"):
            verify(self.directory)


if __name__ == "__main__":
    unittest.main()
