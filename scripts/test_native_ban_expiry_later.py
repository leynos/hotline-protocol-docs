"""Fault controls for the frozen later temporary-ban epoch."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_ban_expiry_later import CORPUS, FIRST, verify


def write(path: Path, value: dict) -> None:
    path.write_text(json.dumps(value, indent=2) + "\n")


def refresh(root: Path) -> None:
    for checksums in root.rglob("checksums.sha256"):
        names = [line.split("  ", 1)[1] for line in checksums.read_text().splitlines()]
        checksums.write_text(
            "".join(
                f"{hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()}  {name}\n"
                for name in names
            )
        )
    manifest = json.loads((root / "manifest.json").read_text())
    manifest["files"] = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    write(root / "manifest.json", manifest)
    (root / "SHA256SUMS").write_text(
        "".join(
            f"{digest}  {name}\n" for name, digest in sorted(manifest["files"].items())
        )
    )


class NativeBanExpiryLaterTest(unittest.TestCase):
    def test_baseline_is_bounded(self) -> None:
        result = verify(CORPUS, FIRST)
        self.assertEqual(result["status"], "verified_later_epoch_only")
        self.assertEqual(result["pre_window"], "missed_no_probe")
        self.assertFalse(result["exact_1800_boundary_proven"])
        self.assertEqual(
            {
                name: (flow["sent_bytes"], flow["received_bytes"])
                for name, flow in result["later_flows"].items()
            },
            {
                "post": (120, 389),
                "guard": (169, 496),
                "delete": (274, 645),
                "postflight": (231, 2759),
            },
        )

    def mutate(self, change, reason: str) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / CORPUS.name
            shutil.copytree(CORPUS, root)
            change(root)
            refresh(root)
            with self.assertRaisesRegex((ValueError, KeyError), reason):
                verify(root, FIRST)

    def edit(self, path: str, change, reason: str) -> None:
        def apply(root: Path) -> None:
            file = root / path
            data = json.loads(file.read_text())
            change(data)
            write(file, data)

        self.mutate(apply, reason)

    def test_forged_post_window(self) -> None:
        self.edit(
            "raw/post/results/summary.json",
            lambda data: data["timing_gate"].update(host_elapsed_seconds=1800),
            "Post first lookup|timing",
        )

    def test_wrong_live_start_tick(self) -> None:
        self.edit(
            "raw/post/capture-ready.json",
            lambda data: data.update(emulator_starttime="5983215"),
            "continuity",
        )

    def test_forged_pre_window(self) -> None:
        self.mutate(
            lambda root: (root / "raw/pre/c80-failed-unit.txt").write_text(
                "Result=success\nExecMainStatus=0\n"
            ),
            "failed-before-socket",
        )

    def test_post_case_omission(self) -> None:
        self.edit(
            "raw/post/results/summary.json",
            lambda data: data.update(cases={}),
            "Post first lookup",
        )

    def test_guard_wrong_owned_key(self) -> None:
        def change(data: dict) -> None:
            step = data["steps"][7]
            self.assertEqual(step["op"], "send")
            self.assertTrue(step["hex"].endswith("65726f"))
            step["hex"] = step["hex"][:-2] + "70"

        self.edit("raw/post/cleanup-guard-plan/plan.json", change, "guard source plan")

    def test_delete_plan_new_account(self) -> None:
        self.edit(
            "raw/post/cleanup-delete-plan/plan.json",
            lambda data: data["steps"].append({"op": "close", "connection": "main"}),
            "delete/readback source plan",
        )

    def test_missing_postflight(self) -> None:
        self.edit(
            "raw/post/postflight/report.json",
            lambda data: data.update(completed_actions=17),
            "Incomplete plan",
        )

    def test_packet_tail_corruption(self) -> None:
        def change(root: Path) -> None:
            path = root / "raw/post/lab-namespace.pcap"
            data = bytearray(path.read_bytes())
            offset = data.find(b"Expiry Zero")
            self.assertGreater(offset, 0)
            data[offset] ^= 1
            path.write_bytes(data)
            receipt = root / "raw/post/terminal.json"
            value = json.loads(receipt.read_text())
            value["namespace_pcap"]["sha256"] = hashlib.sha256(data).hexdigest()
            write(receipt, value)

        self.mutate(change, "paired TCP bytes|tail|flow")

    def test_clock_claim_changes(self) -> None:
        self.edit(
            "raw/post/clock-witness.json",
            lambda data: data["post_probe"].update(
                visible_guest_menubar_clock="Sat 6:00:00 AM"
            ),
            "Guest clock",
        )

    def test_capture_drop_is_rejected(self) -> None:
        self.mutate(
            lambda root: (root / "raw/post/namespace-terminal-journal.log").write_text(
                "1 packets dropped by kernel\n"
            ),
            "capture drops",
        )

    def test_source_correction_changes(self) -> None:
        self.mutate(
            lambda root: (
                root / "raw/post/sources/native_ban_expiry_control.py"
            ).write_text("# forged source\n"),
            "start-tick correction",
        )

    def test_allocated_trash_fingerprint_changes(self) -> None:
        self.mutate(
            lambda root: (root / "raw/post/stopped-allocated-catalog.txt").write_text(
                "Banned\n"
            ),
            "Banned file|allocated Trash",
        )

    def test_fd_free_boundary_changes(self) -> None:
        self.edit(
            "raw/post/stopped-read-gate.json",
            lambda data: data.update(image_fd_owners=[[774195, 6]]),
            "FD-free",
        )


if __name__ == "__main__":
    unittest.main()
