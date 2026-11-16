"""Semantic fault controls for the frozen configured-address ban witness."""

import hashlib
import json
import tempfile
import typing as typ
from pathlib import Path
from shutil import copytree

import pytest
from protocol_capture import Recorder, decode_frame
from verify_native_configured_ban import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/native-configured-ban-01"
)
CASE = Path("native-configured-apply-c66")
HELD = CASE / "captures/held-apply"


def write_json(path: Path, value: dict) -> None:
    """Write ``value`` to ``path`` as indented JSON with a final newline."""
    path.write_text(json.dumps(value, indent=2) + "\n")


def update_inventory(root: Path) -> None:
    """Refresh the manifest file list and the SHA256SUMS inventory of ``root``."""
    manifest = json.loads((root / "manifest.json").read_text())
    files = {
        str(path.relative_to(root)): hashlib.sha256(path.read_bytes()).hexdigest()
        for path in root.rglob("*")
        if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
    }
    manifest["files"] = files
    write_json(root / "manifest.json", manifest)
    (root / "SHA256SUMS").write_text(
        "".join(f"{value}  {name}\n" for name, value in sorted(files.items()))
    )


def replay_frames(report: dict, plan: dict) -> None:
    """Rebuild the decoded frames of ``report`` from its recorded events."""
    recorder = Recorder(plan)
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
            length = 20 + int.from_bytes(data[16:20], "big")
            frames.append({
                "action": action,
                "connection": step["connection"],
                **decode_frame(data[:length]),
            })
            data = data[length:]
    report["frames"] = frames


class ConfiguredBanWitnessTest:
    """Check the frozen configured-address ban witness against semantic faults."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def test_frozen_corpus(self) -> None:
        """Check the connection count and the ban byte count of the frozen corpus."""
        result = verify(CORPUS)
        assert result["connections"] == 5, "the connection count differs"
        assert result["ban_bytes"] == 49, "the ban byte count differs"

    def mutate(self, change: cabc.Callable[[Path], object], reason: str) -> None:
        """Mutate a copy of the frozen corpus and expect ``verify`` to reject it.

        Parameters
        ----------
        change : collections.abc.Callable[[pathlib.Path], object]
            Applied to the copied corpus root before its inventory is refreshed.
        reason : str
            The pattern that the rejection message must match.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / "native-configured-ban-01"
            copytree(CORPUS, root)
            change(root)
            update_inventory(root)
            with pytest.raises(ValueError, match=reason):
                verify(root)

    def edit_json(
        self, relative: Path, change: cabc.Callable[[dict], object], reason: str
    ) -> None:
        """Edit one JSON file of the copied corpus and expect a rejection.

        Parameters
        ----------
        relative : pathlib.Path
            The file, relative to the corpus root.
        change : collections.abc.Callable[[dict], object]
            Applied to the parsed JSON value of the file.
        reason : str
            The pattern that the rejection message must match.
        """

        def apply(root: Path) -> None:
            """Apply ``change`` to the JSON file under ``root``."""
            path = root / relative
            value = json.loads(path.read_text())
            change(value)
            write_json(path, value)

        self.mutate(apply, reason)

    def edit_report(
        self, phase: str, change: cabc.Callable[[dict], object], reason: str
    ) -> None:
        """Edit the report of one phase, replay its frames and expect a rejection.

        Parameters
        ----------
        phase : str
            The capture phase directory, such as ``held-apply``.
        change : collections.abc.Callable[[dict], object]
            Applied to the parsed report before its frames are replayed.
        reason : str
            The pattern that the rejection message must match.
        """

        def apply(root: Path) -> None:
            """Apply ``change`` to a phase report and re-checksum the folder."""
            folder = root / CASE / "captures" / phase
            report = json.loads((folder / "report.json").read_text())
            plan = json.loads((folder / "plan.json").read_text())
            change(report)
            replay_frames(report, plan)
            write_json(folder / "report.json", report)
            lines = []
            for name in ("plan.json", "report.json"):
                value = hashlib.sha256((folder / name).read_bytes()).hexdigest()
                lines.append(f"{value}  {name}\n")
            (folder / "checksums.sha256").write_text("".join(lines))

        self.mutate(apply, reason)

    def test_identity_and_management_faults(self) -> None:
        """Check that each identity and management fault is rejected."""
        cases = (
            (
                Path("native-configured-apply-c65/terminal.json"),
                lambda v: v.update(guest_pcap_present=True),
                "C65 failed-boot status differs",
            ),
            (
                CASE / "process-ready.json",
                lambda v: v["lab"].update(starttime="1"),
                "Actual lab emulator or original identity differs",
            ),
            (
                HELD / "held-ready.json",
                lambda v: v.update(target_uid_hex="0006"),
                "Held current target UID",
            ),
            (
                CASE / "lease-ready.json",
                lambda v: v.update(busy_flock_exit=0),
                "Managed oracle lockholder differs",
            ),
            (
                CASE / "terminal.json",
                lambda v: v.update(actual_lab_pid_gone=False),
                "Lab retirement",
            ),
        )
        for path, change, reason in cases:
            self.edit_json(path, change, reason)

    def test_source_packet_drop_and_stored_bytes(self) -> None:
        """Check that source, drop and stored-byte faults are each rejected."""

        def alter(root: Path, name: Path, old: bytes, new: bytes) -> None:
            """Replace the first ``old`` bytes under ``root`` with ``new``."""
            path = root / name
            data = path.read_bytes()
            assert old in data, f"{name} lacks the expected bytes"
            path.write_bytes(data.replace(old, new, 1))

        cases = (
            (
                Path("sources/protocol/native_configured_ban_cases.py"),
                b"import ",
                b"# changed\nimport ",
                "Controller source snapshot differs",
            ),
            (
                CASE / "namespace-recorder.log",
                b"0 packets dropped by kernel",
                b"1 packets dropped by kernel",
                "namespace capture drops differ",
            ),
            (
                CASE / "stopped-files/Banned.bin",
                b"\x00\x02\x00\x00",
                b"\x00\x03\x00\x00",
                "Stopped stored file bytes differ",
            ),
        )
        for name, old, new, reason in cases:
            self.mutate(
                lambda root, name=name, old=old, new=new: alter(root, name, old, new),
                reason,
            )

    def test_zero_privilege_bitmap_required(self) -> None:
        """Check that a zero-privilege bitmap is required in the held apply phase."""

        def change(report: dict) -> None:
            """Set the final byte of the short action-12 receive to one."""
            event = next(
                e
                for e in report["events"]
                if e["action"] == 12 and e["event"] == "receive" and len(e["hex"]) < 40
            )
            raw = bytearray.fromhex(event["hex"])
            raw[-1] = 1
            event["hex"] = raw.hex()

        self.edit_report(
            "held-apply", change, "Owned target login or zero access differs"
        )

    def test_save_handoff_and_early_notice(self) -> None:
        """Check that the Save handoff and an early notice are each rejected."""
        reason = "Add, reviewed Save or early-data timing differs"
        self.mutate(
            lambda root: (root / CASE / "save-trigger.utc").write_text(
                "2026-11-14T04:49:00+00:00\n"
            ),
            reason,
        )

        def early(report: dict) -> None:
            """Move the action-17 notice sixty seconds later."""
            next(
                e
                for e in report["events"]
                if e["action"] == 17 and e["event"] == "receive"
            )["elapsed_ns"] = 60_000_000_000

        self.edit_report("held-apply", early, reason)

    def test_notice_type_and_text(self) -> None:
        """Check that the notice type and its text are each rejected when altered."""
        for position, byte, reason in (
            (3, 105, "Completed frame read did not match"),
            (-1, ord("!"), "main configured-ban notice differs"),
        ):

            def change(
                report: dict, position: int = position, byte: int = byte
            ) -> None:
                """Overwrite one byte of the action-17 notice."""
                event = next(
                    e
                    for e in report["events"]
                    if e["action"] == 17
                    and e["event"] == "receive"
                    and (position == 3 or len(e["hex"]) > 40)
                )
                raw = bytearray.fromhex(event["hex"])
                raw[position] = byte
                event["hex"] = raw.hex()

            self.edit_report("held-apply", change, reason)

    def test_target_eof_required(self) -> None:
        """Check that the target close is required in the held apply phase."""
        self.edit_report(
            "held-apply",
            lambda report: report.update(
                events=[
                    e
                    for e in report["events"]
                    if not (e["action"] == 20 and e["event"] == "eof")
                ]
            ),
            "target close missing",
        )

    def test_extra_request_110_forbidden(self) -> None:
        """Check that an extra 110 request is forbidden in the held apply phase."""

        def change(report: dict) -> None:
            """Rewrite the action-15 request type to 110."""
            event = next(
                e
                for e in report["events"]
                if e["action"] == 15 and e["event"] == "send"
            )
            raw = bytearray.fromhex(event["hex"])
            raw[2:4] = (110).to_bytes(2, "big")
            event["hex"] = raw.hex()

        self.edit_report("held-apply", change, "110 request forbidden")

    def test_paired_guest_byte_mismatch(self) -> None:
        """Check that a byte mismatch in the paired guest capture is rejected."""

        def change(root: Path) -> None:
            """Flip one bit of the paired guest capture."""
            path = root / CASE / "lab-guest.pcap"
            raw = bytearray(path.read_bytes())
            at = raw.index(b"TRTPHOTL")
            raw[at + 7] ^= 1
            path.write_bytes(raw)

        self.mutate(change, "Conflicting TCP retransmission|paired TCP bytes differ")
