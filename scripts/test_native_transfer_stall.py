"""Meaningful offline fault controls for the C35 failed-transfer corpus."""

import hashlib
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from verify_native_transfer_stall import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-transfer-stall-01"
)


class TransferStallTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.corpus = Path(temporary.name) / "native-transfer-stall-01"
        shutil.copytree(CORPUS, self.corpus)

    def reseal(self, relative: str) -> None:
        provenance_path = self.corpus / "source-provenance.json"
        provenance = json.loads(provenance_path.read_text())
        if relative in provenance["sources"]:
            path = self.corpus / relative
            provenance["sources"][relative]["sha256"] = hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            provenance["sources"][relative]["bytes"] = path.stat().st_size
            provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
        manifest_path = self.corpus / "manifest.json"
        manifest = json.loads(manifest_path.read_text())
        for name in (relative, "source-provenance.json"):
            manifest["files"][name] = hashlib.sha256(
                (self.corpus / name).read_bytes()
            ).hexdigest()
        manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
        (self.corpus / "SHA256SUMS").write_text(
            "".join(
                f"{value}  {name}\n"
                for name, value in sorted(manifest["files"].items())
            )
        )

    def test_original_failure_and_packet_views_replay(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["status"], "verified_failed_baseline")
        self.assertFalse(result["option_two_executed"])

    def test_resealed_success_claim_cannot_replace_failed_report(self) -> None:
        relative = "failure/report.json"
        path = self.corpus / relative
        report = json.loads(path.read_text())
        report["status"] = "completed"
        path.write_text(json.dumps(report, indent=2) + "\n")
        checksums = self.corpus / "failure/checksums.sha256"
        checksums.write_text(
            "".join(
                f"{hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ("plan.json", "report.json")
            )
        )
        self.reseal(relative)
        self.reseal("failure/checksums.sha256")
        with self.assertRaisesRegex(
            ValueError, "Incomplete plan reported as completed"
        ):
            verify(self.corpus)

    def test_resealed_zero_receive_window_changes_h2_result(self) -> None:
        relative = "capture/namespace.pcap"
        path = self.corpus / relative
        raw = bytearray(path.read_bytes())
        offset = 24
        for index in range(1, 179):
            _, _, size, _ = struct.unpack_from("<IIII", raw, offset)
            if index == 178:
                ip = offset + 16 + 14
                tcp = ip + (raw[ip] & 15) * 4
                raw[tcp + 14 : tcp + 16] = b"\0\0"
                break
            offset += 16 + size
        path.write_bytes(raw)
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "namespace zero window"):
            verify(self.corpus)

    def test_resealed_truncated_guest_packet_is_rejected(self) -> None:
        relative = "capture/guest.pcap"
        path = self.corpus / relative
        path.write_bytes(path.read_bytes()[:-1])
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "Truncated packet bytes"):
            verify(self.corpus)


if __name__ == "__main__":
    unittest.main()
