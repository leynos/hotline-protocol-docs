"""Fault controls for the frozen C50 focus-event result."""

import hashlib
import json
import shutil
import struct
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import read_packets
from verify_native_ui_focus import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/native-ui-focus-01"
)


class NativeUiFocusTests(unittest.TestCase):
    def setUp(self) -> None:
        temporary = tempfile.TemporaryDirectory()
        self.addCleanup(temporary.cleanup)
        self.corpus = Path(temporary.name) / "native-ui-focus-01"
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

    def test_frozen_negative_focus_replays(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["guest_bytes"], 98_304)
        self.assertEqual(result["event_count"], 1)
        self.assertFalse(result["option_two_executed"])

    def test_resealed_zero_click_claim_is_rejected(self) -> None:
        relative = "experiment/focus-event/result.json"
        path = self.corpus / relative
        result = json.loads(path.read_text())
        result["event_count"] = 0
        path.write_text(json.dumps(result, indent=2) + "\n")
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "Focus event outcome differs"):
            verify(self.corpus)

    def test_resealed_unchanged_title_is_rejected(self) -> None:
        relative = "experiment/focus-event/after.png"
        path = self.corpus / relative
        path.write_bytes(path.with_name("before.png").read_bytes())
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "Activated Log title differs"):
            verify(self.corpus)

    def test_resealed_guest_payload_corruption_is_rejected(self) -> None:
        relative = "boot/lab-guest.pcap"
        path = self.corpus / relative
        packets = read_packets(path)
        index = next(
            p["index"]
            for p in packets
            if p["src_ip"] == "10.0.2.15" and p["src_port"] == 5501 and p["payload_hex"]
        )
        raw = bytearray(path.read_bytes())
        offset = 24
        for number in range(1, index + 1):
            _, _, size, _ = struct.unpack_from("<IIII", raw, offset)
            if number == index:
                raw[offset + 16 + size - 1] ^= 1
                break
            offset += 16 + size
        path.write_bytes(raw)
        self.reseal(relative)
        with self.assertRaisesRegex(ValueError, "guest packet stream differs"):
            verify(self.corpus)

    def test_resealed_false_a7_success_is_rejected(self) -> None:
        relative = "experiment/capture/report.json"
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
        self.reseal("experiment/capture/checksums.sha256")
        with self.assertRaisesRegex(
            ValueError, "Incomplete plan reported as completed"
        ):
            verify(self.corpus)


if __name__ == "__main__":
    unittest.main()
