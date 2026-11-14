"""Semantic fault controls for the frozen first temporary-ban epoch."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_ban_expiry_first import CORPUS, frozen_modules, verify

RAW = Path("raw")
FIRST = RAW / "results-first-c77"


def write_json(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def refresh(root: Path) -> None:
    frozen = json.loads((root / "raw-freeze.json").read_text())
    for name, meta in frozen["files"].items():
        path = root / RAW / name
        meta["copied_size"] = path.stat().st_size
        meta["source_size_after"] = path.stat().st_size
        meta["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    write_json(root / "raw-freeze.json", frozen)
    manifest = json.loads((root / "manifest.json").read_text())
    files = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    manifest["files"] = files
    write_json(root / "manifest.json", manifest)
    (root / "SHA256SUMS").write_text(
        "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
    )


def replay(report: dict, plan: dict) -> None:
    capture = frozen_modules(CORPUS)[2]
    recorder = capture.Recorder(plan)
    recorder.events = report["events"]
    report["streams"] = recorder.streams()
    frames = []
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "read_frame":
            continue
        data = bytes.fromhex(
            "".join(
                event["hex"]
                for event in report["events"]
                if event["action"] == action
                and event["connection"] == step["connection"]
                and event["event"] == "receive"
            )
        )
        while data:
            size = 20 + int.from_bytes(data[16:20], "big")
            frames.append(
                {
                    "action": action,
                    "connection": step["connection"],
                    **capture.decode_frame(data[:size]),
                }
            )
            data = data[size:]
    report["frames"] = frames


class NativeBanExpiryFirstTest(unittest.TestCase):
    def test_baseline(self) -> None:
        result = verify(CORPUS)
        self.assertEqual((result["cases"], result["connections"]), (9, 13))
        self.assertFalse(result["expiry_proven"])

    def mutate(self, change, reason: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / CORPUS.name
            shutil.copytree(CORPUS, root)
            change(root)
            refresh(root)
            with self.assertRaisesRegex((ValueError, KeyError), reason):
                verify(root)

    def edit_json(self, relative: Path, change, reason: str) -> None:
        def apply(root: Path) -> None:
            path = root / relative
            value = json.loads(path.read_text())
            change(value)
            write_json(path, value)

        self.mutate(apply, reason)

    def edit_case(self, name: str, change, reason: str) -> None:
        def apply(root: Path) -> None:
            folder = root / FIRST / name
            report = json.loads((folder / "report.json").read_text())
            plan = json.loads((folder / "plan.json").read_text())
            change(report)
            replay(report, plan)
            write_json(folder / "report.json", report)

        self.mutate(apply, reason)

    def test_wrong_current_uid(self) -> None:
        self.edit_case(
            "tempban",
            lambda report: report["variables"].update(target_uid="0009"),
            "Current target UID|UID",
        )

    def test_wrong_zero_acl(self) -> None:
        def change(report: dict) -> None:
            event = next(
                e
                for e in report["events"]
                if e["action"] == 10 and e["event"] == "receive" and len(e["hex"]) > 40
            )
            raw = bytearray.fromhex(event["hex"])
            raw[-1] ^= 1
            event["hex"] = raw.hex()

        self.edit_case("seed-zero", change, "Owned account readback/access differs")

    def test_wrong_temporary_notice(self) -> None:
        def change(report: dict) -> None:
            event = next(
                e
                for e in report["events"]
                if e["action"] == 18 and e["event"] == "receive" and len(e["hex"]) > 40
            )
            raw = bytearray.fromhex(event["hex"])
            raw[-1] = ord("!")
            event["hex"] = raw.hex()

        self.edit_case("tempban", change, "Temporary notice text differs")

    def test_wrong_ban_time(self) -> None:
        self.edit_json(
            FIRST / "ban-clock.json",
            lambda value: value.update(request_utc="2026-11-14T05:54:01+00:00"),
            "Ban request/ACK bracket differs",
        )

    def test_wrong_namespace_and_deadline(self) -> None:
        for key, value, reason in (
            ("emulator_netns", "net:[42]", "Actual emulator identity"),
            ("deadline_utc", "2026-11-14T06:56:51+00:00", "Actual emulator identity"),
        ):
            with self.subTest(key=key):
                self.edit_json(
                    RAW / "capture-ready.json",
                    lambda obj, key=key, value=value: obj.update({key: value}),
                    reason,
                )

    def test_failed_launch_cannot_be_reported_as_native_rejection(self) -> None:
        self.edit_json(
            RAW / "results-first/guard-zero/report.json",
            lambda value: value.update(completed_actions=1),
            "Failed C76 or corrected C77 launch identity differs",
        )

    def test_paired_tcp_byte_mismatch(self) -> None:
        def change(root: Path) -> None:
            path = root / RAW / "lab-namespace.pcap"
            raw = bytearray(path.read_bytes())
            at = raw.index(b"TRTPHOTL")
            raw[at + 7] ^= 1
            path.write_bytes(raw)

        self.mutate(change, "Conflicting TCP retransmission|paired TCP bytes differ")

    def test_primary_syn_and_drop_receipts(self) -> None:
        def change(root: Path) -> None:
            path = root / RAW / "host-terminal-journal.log"
            path.write_bytes(
                path.read_bytes().replace(
                    b"0 packets dropped by kernel", b"1 packets dropped by kernel"
                )
            )

        self.mutate(change, "Capture drop or owned cleanup differs")

    def test_frozen_controller_mismatch(self) -> None:
        self.mutate(
            lambda root: (
                root / "sources/protocol/native_ban_expiry_control.py"
            ).write_bytes(
                (root / "sources/protocol/native_ban_expiry_control.py").read_bytes()
                + b"\n# changed\n"
            ),
            "Frozen source snapshot differs|As-run B68 source differs",
        )

    def test_protected_unread_tail_is_retained(self) -> None:
        def change(root: Path) -> None:
            path = root / RAW / "lab-guest.pcap"
            data = path.read_bytes()
            tail = bytes.fromhex(
                "0000012e00000004000000000000000800000008000100670002000a"
            )
            at = data.find(tail)
            self.assertGreaterEqual(at, 0)
            raw = bytearray(data)
            raw[at + len(tail) - 1] ^= 1
            path.write_bytes(raw)

        self.mutate(change, "paired TCP bytes differ|Conflicting TCP retransmission")


if __name__ == "__main__":
    unittest.main()
