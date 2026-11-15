"""Semantic fault controls for the three-run frozen transfer corpus."""

import hashlib
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from verify_native_transfer_repeat import verify

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-transfer-repeat-01"
)


class TransferRepeatTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.corpus = Path(temporary.name) / "native-transfer-repeat-01"
        shutil.copytree(CORPUS, self.corpus)

    def reseal(self, relative: str) -> None:
        provenance_path = self.corpus / "source-provenance.json"
        provenance = json.loads(provenance_path.read_text())
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
                f"{digest}  {name}\n"
                for name, digest in sorted(manifest["files"].items())
            )
        )

    def test_complete_and_two_failed_streams_replay(self) -> None:
        results = verify(CORPUS)
        self.assertEqual(results["c32"]["bytes"], 1_049_073)
        self.assertEqual(results["c35"]["bytes"], results["c45"]["bytes"])

    def test_resealed_failed_report_cannot_claim_completion(self) -> None:
        relative = "runs/c45/capture/report.json"
        path = self.corpus / relative
        report = json.loads(path.read_text())
        report["status"] = "completed"
        path.write_text(json.dumps(report, indent=2) + "\n")
        checksums = path.with_name("checksums.sha256")
        checksums.write_text(
            "".join(
                f"{hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ("plan.json", "report.json")
            )
        )
        self.reseal(relative)
        self.reseal("runs/c45/capture/checksums.sha256")
        with self.assertRaisesRegex(
            ValueError, "Incomplete plan reported as completed"
        ):
            verify(self.corpus)

    def test_resealed_success_pcap_missing_byte_is_rejected(self) -> None:
        relative = "runs/c32/boot/lab-guest.pcap"
        path = self.corpus / relative
        data = bytearray(path.read_bytes())
        comparison = json.loads(
            (self.corpus / "analysis/packet-comparison.json").read_text()
        )
        index = comparison["runs"]["c32"]["views"]["guest"]["last_server_packet_index"]
        offset = 24
        for number in range(1, index + 1):
            _, _, size, _ = struct.unpack_from("<IIII", data, offset)
            if number == index:
                data[offset + 16 + size - 1] ^= 1
                break
            offset += 16 + size
        path.write_bytes(data)
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "c32 guest payload differs"):
            verify(self.corpus)

    def test_resealed_changed_a7_step_is_rejected(self) -> None:
        relative = "runs/c35/original-plan.json"
        path = self.corpus / relative
        plan = json.loads(path.read_text())
        plan["steps"].pop()
        path.write_text(json.dumps(plan, indent=2) + "\n")
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "c35 source A7 differs"):
            verify(self.corpus)

    def test_resealed_c45_cleanup_scope_is_rejected(self) -> None:
        relative = "runs/c45/terminal.json"
        path = self.corpus / relative
        terminal = json.loads(path.read_text())
        terminal["guard_seed_ban_probe"] = "option two executed"
        path.write_text(json.dumps(terminal, indent=2) + "\n")
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "C45 option-two scope differs"):
            verify(self.corpus)


if __name__ == "__main__":
    unittest.main()
