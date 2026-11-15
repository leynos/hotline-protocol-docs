"""Checksum-updated faults for the bounded A29 PM corpus."""

import copy
import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from verify_native_pm_packet import verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-pm-01"
)


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def rebuild_streams(report: dict) -> None:
    streams = {}
    for event in report["events"]:
        name = event["connection"]
        if not name:
            continue
        saved = streams.setdefault(name, {"sent_hex": "", "received_hex": ""})
        if event["event"] == "send":
            saved["sent_hex"] += event["hex"]
        elif event["event"] == "receive":
            saved["received_hex"] += event["hex"]
    report["streams"] = streams


def change_field(report: dict, action: int, field_id: int, new_value: bytes) -> None:
    frame = next(f for f in report["frames"] if f["action"] == action)
    payload = bytearray.fromhex(frame["payload_hex"])
    offset = 2
    for field in frame["fields"]:
        identifier = int.from_bytes(payload[offset : offset + 2], "big")
        size = int.from_bytes(payload[offset + 2 : offset + 4], "big")
        if identifier == field_id:
            if len(new_value) != size:
                raise ValueError("Test mutation must preserve field width")
            payload[offset + 4 : offset + 4 + size] = new_value
            field["hex"] = new_value.hex()
            break
        offset += 4 + size
    else:
        raise ValueError("Test field absent")
    frame["payload_hex"] = payload.hex()
    receives = [
        e for e in report["events"] if e["action"] == action and e["event"] == "receive"
    ]
    if len(receives) != 2:
        raise ValueError("Expected header and one payload read")
    receives[1]["hex"] = payload.hex()
    rebuild_streams(report)


class PMPacketTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        self.root = Path(self.temporary.name)
        self.manifest = json.loads((BATCH / "manifest.json").read_text())
        for path in self.manifest["files"]:
            target = self.root / path
            target.parent.mkdir(parents=True, exist_ok=True)
            target.symlink_to(BATCH / path)

    def replace(self, path: str, data: bytes) -> None:
        target = self.root / path
        target.unlink()
        target.write_bytes(data)
        self.manifest["files"][path] = sha(data)

    def seal(self) -> None:
        data = (json.dumps(self.manifest, indent=2) + "\n").encode()
        (self.root / "manifest.json").write_bytes(data)
        checks = {**self.manifest["files"], "manifest.json": sha(data)}
        (self.root / "SHA256SUMS").write_text(
            "".join(f"{value}  {path}\n" for path, value in sorted(checks.items()))
        )

    def report(self) -> dict:
        return copy.deepcopy(json.loads((BATCH / "observe/report.json").read_text()))

    def test_original_corpus(self) -> None:
        self.seal()
        self.assertEqual(verify(self.root)["status"], "verified-bounded-native-pm")

    def test_rehashed_wrong_uid_option_and_quote(self) -> None:
        for action, field, value in [
            (33, 103, b"\0\x2d"),
            (33, 113, b"\0\x02"),
            (33, 214, b"quote-b26"),
        ]:
            with self.subTest(field=field):
                report = self.report()
                change_field(report, action, field, value)
                self.replace(
                    "observe/report.json",
                    (json.dumps(report, indent=2) + "\n").encode(),
                )
                checks = {
                    "plan.json": sha((self.root / "observe/plan.json").read_bytes()),
                    "report.json": self.manifest["files"]["observe/report.json"],
                }
                self.replace(
                    "observe/checksums.sha256",
                    "".join(f"{v}  {k}\n" for k, v in checks.items()).encode(),
                )
                self.seal()
                with self.assertRaisesRegex(
                    ValueError, "PM 104|PM routing|PM semantic|PM quoted"
                ):
                    verify(self.root)

    def test_missing_delivery_rejected(self) -> None:
        report = self.report()
        report["frames"] = [f for f in report["frames"] if f["action"] != 33]
        report["events"] = [e for e in report["events"] if e["action"] != 33]
        rebuild_streams(report)
        self.replace(
            "observe/report.json", (json.dumps(report, indent=2) + "\n").encode()
        )
        checks = {
            "plan.json": sha((self.root / "observe/plan.json").read_bytes()),
            "report.json": self.manifest["files"]["observe/report.json"],
        }
        self.replace(
            "observe/checksums.sha256",
            "".join(f"{v}  {k}\n" for k, v in checks.items()).encode(),
        )
        self.seal()
        with self.assertRaisesRegex(ValueError, "Completed frame read|Decoded frame"):
            verify(self.root)

    def test_packet_mismatch_rejected_after_rehash(self) -> None:
        raw = (BATCH / "host-after-observe.pcap").read_bytes()
        self.assertIn(b"pm-a26-direct", raw)
        self.replace(
            "host-after-observe.pcap",
            raw.replace(b"pm-a26-direct", b"pm-a26-difect", 1),
        )
        self.seal()
        with self.assertRaisesRegex(ValueError, "TCP|packet reconciliation"):
            verify(self.root)

    def test_truncated_a7_rejected_after_rehash(self) -> None:
        plan = json.loads((BATCH / "postflight/plan.json").read_text())
        plan["steps"] = plan["steps"][:18]
        self.replace(
            "postflight/plan.json", (json.dumps(plan, indent=2) + "\n").encode()
        )
        checks = {
            "plan.json": self.manifest["files"]["postflight/plan.json"],
            "report.json": sha((self.root / "postflight/report.json").read_bytes()),
        }
        self.replace(
            "postflight/checksums.sha256",
            "".join(f"{v}  {k}\n" for k, v in checks.items()).encode(),
        )
        self.seal()
        with self.assertRaisesRegex(
            ValueError, "Source identity|Incomplete plan|plan differs"
        ):
            verify(self.root)


if __name__ == "__main__":
    unittest.main()
