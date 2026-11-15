"""Reject semantic and packet faults even after the mutable inventory is rehashed."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_settings_corpus import verify

BUNDLE = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-settings-01"
)


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeSettingsCorpusTests(unittest.TestCase):
    def mutate(self, change, reason: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            shutil.copytree(BUNDLE, bundle)
            changed = change(bundle)
            if changed.name == "report.json":
                capture = changed.parent
                (capture / "checksums.sha256").write_text(
                    "".join(
                        f"{digest(capture / name)}  {name}\n"
                        for name in ["plan.json", "report.json"]
                    )
                )
            raw = bundle / "raw"
            (raw / "SHA256SUMS").write_text(
                "".join(
                    f"{digest(path)}  {path.relative_to(raw)}\n"
                    for path in sorted(raw.rglob("*"))
                    if path.is_file() and path.name != "SHA256SUMS"
                )
            )
            manifest = json.loads((bundle / "manifest.json").read_text())
            manifest["raw_sha256sums_sha256"] = digest(raw / "SHA256SUMS")
            (bundle / "manifest.json").write_text(json.dumps(manifest) + "\n")
            with self.assertRaisesRegex(ValueError, reason):
                verify(bundle)

    def test_original_offline_bundle(self) -> None:
        result = verify(BUNDLE)
        self.assertEqual(
            (result["status"], len(result["cases"]), result["paired_sockets"]),
            ("verified", 10, 24),
        )
        self.assertEqual(result["a7"]["postflight"]["filp_bytes"], 1049073)

    def test_rehashed_wrong_flags(self) -> None:
        def change(bundle: Path) -> Path:
            path = bundle / "raw/cases/one-byte-refuse/report.json"
            report = json.loads(path.read_text())
            feedback = next(
                f
                for f in report["frames"]
                if f["connection"] == "main" and f["type"] == 104
            )
            next(f for f in feedback["fields"] if f["id"] == 113)["hex"] = "0004"
            path.write_text(json.dumps(report) + "\n")
            return path

        self.mutate(change, "Field-113 state differs")

    def test_rehashed_missing_delivery(self) -> None:
        def change(bundle: Path) -> Path:
            path = bundle / "raw/cases/absent/report.json"
            report = json.loads(path.read_text())
            report["frames"] = [
                f
                for f in report["frames"]
                if not (f["connection"] == "subject" and f["type"] == 104)
            ]
            path.write_text(json.dumps(report) + "\n")
            return path

        self.mutate(change, "Suppression without refusal feedback")

    def test_rehashed_spoofed_uid(self) -> None:
        def change(bundle: Path) -> Path:
            path = bundle / "raw/cases/absent/report.json"
            report = json.loads(path.read_text())
            updates = [
                f
                for f in report["frames"]
                if f["connection"] == "main" and f["type"] == 301
            ]
            next(f for f in updates[1]["fields"] if f["id"] == 103)["hex"] = "ffff"
            path.write_text(json.dumps(report) + "\n")
            return path

        self.mutate(change, "Subject UID changed")

    def test_rehashed_altered_host_pcap(self) -> None:
        def change(bundle: Path) -> Path:
            path = bundle / "raw/host.pcap"
            value = bytearray(path.read_bytes())
            value[0] ^= 0xFF
            path.write_bytes(value)
            return path

        self.mutate(change, "PCAP")

    def test_rehashed_shortened_a7_data(self) -> None:
        def change(bundle: Path) -> Path:
            path = bundle / "raw/postflight/capture/report.json"
            report = json.loads(path.read_text())
            report["streams"]["download"]["received_hex"] = report["streams"][
                "download"
            ]["received_hex"][:-2]
            path.write_text(json.dumps(report) + "\n")
            return path

        self.mutate(change, "A7 FILP transfer length differs")


if __name__ == "__main__":
    unittest.main()
