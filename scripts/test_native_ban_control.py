"""Fault controls for the frozen isolated option-two witness."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path
from shutil import copytree

import native_control_readiness as gates
from verify_native_ban_control import verify

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-ban-control-01"
)


class NativeBanControlTest(unittest.TestCase):
    def report(self, phase: str) -> dict:
        return json.loads(
            (CORPUS / f"case-c56/captures/{phase}/report.json").read_text()
        )

    def test_frozen_corpus(self) -> None:
        self.assertEqual(verify(CORPUS)["connections"], 6)

    def test_wrong_target_identity(self) -> None:
        frames = copy.deepcopy(self.report("ban")["frames"])
        join = next(f for f in frames if f["type"] == 301)
        next(f for f in join["fields"] if f["id"] == 102)["hex"] = "78"
        with self.assertRaisesRegex(ValueError, "Target UID/name mismatch"):
            gates.target_gate(frames)

    def test_wrong_permanent_notice(self) -> None:
        report = self.report("ban")
        notice = next(f for f in report["frames"] if f["type"] == 104)
        next(f for f in notice["fields"] if f["id"] == 101)["hex"] = "78"
        with self.assertRaisesRegex(ValueError, "Permanent notice differs"):
            gates.outcome(report)

    def test_target_must_close(self) -> None:
        report = self.report("ban")
        report["events"] = [
            e
            for e in report["events"]
            if (e["connection"], e["event"]) != ("target", "eof")
        ]
        with self.assertRaisesRegex(ValueError, "Target close missing"):
            gates.outcome(report)

    def test_post_ban_readback_required(self) -> None:
        report = self.report("ban")
        report["frames"] = [
            f for f in report["frames"] if not (f["is_reply"] and f["id"] == 42)
        ]
        with self.assertRaises((ValueError, StopIteration)):
            gates.outcome(report)

    def test_fresh_login_107_required(self) -> None:
        report = self.report("probe")
        report["events"] = [
            e
            for e in report["events"]
            if not (e["event"] == "send" and e["hex"].startswith("0000006b"))
        ]
        with self.assertRaisesRegex(ValueError, "Fresh TRTP plus Login107 absent"):
            gates.probe(report)

    def mutate(self, relative: str, replacement: bytes, message: str) -> None:
        with tempfile.TemporaryDirectory() as temp:
            copy = Path(temp) / "corpus"
            copytree(CORPUS, copy)
            (copy / relative).write_bytes(replacement)
            manifest = json.loads((copy / "manifest.json").read_text())
            manifest["files"][relative] = hashlib.sha256(replacement).hexdigest()
            if relative.endswith("/captures/ban/report.json"):
                sums = "case-c56/captures/ban/checksums.sha256"
                (copy / sums).write_text(
                    f"{manifest['files'][relative]}  report.json\n"
                    f"{hashlib.sha256((copy / 'case-c56/captures/ban/plan.json').read_bytes()).hexdigest()}  plan.json\n"
                )
                manifest["files"][sums] = hashlib.sha256(
                    (copy / sums).read_bytes()
                ).hexdigest()
            (copy / "manifest.json").write_text(json.dumps(manifest))
            (copy / "SHA256SUMS").write_text(
                "".join(
                    f"{sha}  {name}\n"
                    for name, sha in sorted(manifest["files"].items())
                )
            )
            with self.assertRaisesRegex(ValueError, message):
                verify(copy)

    def test_rehashed_boot_identity(self) -> None:
        path = "boot-c55/readiness.json"
        value = json.loads((CORPUS / path).read_text())
        value["actual_emulator"]["starttime"] = "1"
        self.mutate(path, json.dumps(value).encode(), "Boot emulator identity differs")

    def test_rehashed_wrong_ban_option(self) -> None:
        path = "case-c56/captures/ban/report.json"
        value = json.loads((CORPUS / path).read_text())
        request = next(
            e
            for e in value["events"]
            if e["event"] == "send" and e["hex"].startswith("0000006e")
        )
        original = request["hex"]
        request["hex"] = original[:-4] + "0001"
        value["streams"]["main"]["sent_hex"] = value["streams"]["main"][
            "sent_hex"
        ].replace(original, request["hex"])
        self.mutate(
            path,
            json.dumps(value).encode(),
            "Control-only request or one-ban scope differs",
        )

    def test_rehashed_packet_drop(self) -> None:
        path = "boot-c55/namespace-recorder.log"
        data = (
            (CORPUS / path)
            .read_bytes()
            .replace(b"0 packets dropped by kernel", b"1 packets dropped by kernel")
        )
        self.mutate(path, data, "namespace packet drops differ")

    def test_rehashed_cleanup(self) -> None:
        path = "case-c56/terminal.json"
        value = json.loads((CORPUS / path).read_text())
        value["actual_pid_gone"] = False
        self.mutate(path, json.dumps(value).encode(), "Terminal profile differs")

    def test_rehashed_persisted_bytes(self) -> None:
        path = "case-c56/Banned.data.bin"
        data = bytearray((CORPUS / path).read_bytes())
        data[-1] ^= 1
        self.mutate(path, bytes(data), "Stopped persisted ban bytes")


if __name__ == "__main__":
    unittest.main()
