"""Semantic fault controls for the frozen first temporary-ban epoch."""

import hashlib
import json
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from ban_expiry_support import iteration
from verify_native_ban_expiry_first import CORPUS, frozen_modules, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

RAW = Path("raw")
FIRST = RAW / "results-first-c77"


def write_json(path: Path, value: dict) -> None:
    """Write a JSON document with two-space indentation and a final newline.

    Parameters
    ----------
    path : Path
        The file to write.
    value : dict
        The document to serialize.
    """
    path.write_text(json.dumps(value, indent=2) + "\n")


def refresh(root: Path) -> None:
    """Re-freeze a mutated corpus so that only its semantics are tested.

    Parameters
    ----------
    root : Path
        The copied corpus to refresh in place.
    """
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
    """Decode the frames of a report again from its recorded events.

    Parameters
    ----------
    report : dict
        The report whose ``frames`` and ``streams`` are rebuilt in place.
    plan : dict
        The plan whose read steps select the events to decode.
    """
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
            frames.append({
                "action": action,
                "connection": step["connection"],
                **capture.decode_frame(data[:size]),
            })
            data = data[size:]
    report["frames"] = frames


class NativeBanExpiryFirstTest:
    """Fault controls for the frozen first temporary-ban epoch."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    def test_baseline(self) -> None:
        """The retained first epoch verifies with its nine cases and 13 connections."""
        result = verify(CORPUS)
        assert (result["cases"], result["connections"]) == (9, 13), "baseline counts"
        assert not result["expiry_proven"], "expiry must not be proven"

    def mutate(self, change: cabc.Callable[[Path], object], reason: str) -> None:
        """Change a copy of the corpus and check that verification rejects it.

        Parameters
        ----------
        change : collections.abc.Callable[[pathlib.Path], None]
            The change to apply to the copied corpus.
        reason : str
            A regular expression that the rejection message must match.
        """
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory) / CORPUS.name
            shutil.copytree(CORPUS, root)
            change(root)
            refresh(root)
            with pytest.raises((ValueError, KeyError), match=reason):
                verify(root)

    def edit_json(
        self, relative: Path, change: cabc.Callable[[dict], None], reason: str
    ) -> None:
        """Change one JSON document of a copied corpus and check the rejection.

        Parameters
        ----------
        relative : pathlib.Path
            The document, relative to the corpus root.
        change : collections.abc.Callable[[dict], None]
            The change to apply to the parsed document.
        reason : str
            A regular expression that the rejection message must match.
        """

        def apply(root: Path) -> None:
            """Apply the change to the document of the copied corpus."""
            path = root / relative
            value = json.loads(path.read_text())
            change(value)
            write_json(path, value)

        self.mutate(apply, reason)

    def edit_case(
        self, name: str, change: cabc.Callable[[dict], None], reason: str
    ) -> None:
        """Change the report of one retained case and check the rejection.

        Parameters
        ----------
        name : str
            The case whose report is changed.
        change : collections.abc.Callable[[dict], None]
            The change to apply to the parsed report.
        reason : str
            A regular expression that the rejection message must match.
        """

        def apply(root: Path) -> None:
            """Apply the change to the report of the copied corpus."""
            folder = root / FIRST / name
            report = json.loads((folder / "report.json").read_text())
            plan = json.loads((folder / "plan.json").read_text())
            change(report)
            replay(report, plan)
            write_json(folder / "report.json", report)

        self.mutate(apply, reason)

    def test_wrong_current_uid(self) -> None:
        """A wrong current target UID is rejected."""
        self.edit_case(
            "tempban",
            lambda report: report["variables"].update(target_uid="0009"),
            "Current target UID|UID",
        )

    def test_wrong_zero_acl(self) -> None:
        """A changed zero-account access byte is rejected."""

        def change(report: dict) -> None:
            """Set the zero-account byte of the seeded event."""
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
        """A changed temporary notice text is rejected."""

        def change(report: dict) -> None:
            """Replace the final byte of the temporary notice."""
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
        """A ban request time outside the ACK bracket is rejected."""
        self.edit_json(
            FIRST / "ban-clock.json",
            lambda value: value.update(request_utc="2026-11-14T05:54:01+00:00"),
            "Ban request/ACK bracket differs",
        )

    def test_wrong_namespace_and_deadline(self) -> None:
        """A wrong emulator namespace or deadline is rejected."""
        for key, value, reason in (
            ("emulator_netns", "net:[42]", "Actual emulator identity"),
            ("deadline_utc", "2026-11-14T06:56:51+00:00", "Actual emulator identity"),
        ):
            with iteration(key):
                self.edit_json(
                    RAW / "capture-ready.json",
                    lambda obj, key=key, value=value: obj.update({key: value}),
                    reason,
                )

    def test_failed_launch_cannot_be_reported_as_native_rejection(self) -> None:
        """A failed launch cannot pass as a native rejection."""
        self.edit_json(
            RAW / "results-first/guard-zero/report.json",
            lambda value: value.update(completed_actions=1),
            "Failed C76 or corrected C77 launch identity differs",
        )

    def test_paired_tcp_byte_mismatch(self) -> None:
        """Differing paired TCP bytes are rejected."""

        def change(root: Path) -> None:
            """Flip one byte of the paired namespace capture."""
            path = root / RAW / "lab-namespace.pcap"
            raw = bytearray(path.read_bytes())
            at = raw.index(b"TRTPHOTL")
            raw[at + 7] ^= 1
            path.write_bytes(raw)

        self.mutate(change, "Conflicting TCP retransmission|paired TCP bytes differ")

    def test_primary_syn_and_drop_receipts(self) -> None:
        """A kernel drop receipt that differs from zero is rejected."""

        def change(root: Path) -> None:
            """Report one packet dropped by the kernel."""
            path = root / RAW / "host-terminal-journal.log"
            path.write_bytes(
                path.read_bytes().replace(
                    b"0 packets dropped by kernel", b"1 packets dropped by kernel"
                )
            )

        self.mutate(change, "Capture drop or owned cleanup differs")

    def test_frozen_controller_mismatch(self) -> None:
        """A changed frozen controller source is rejected."""
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
        """A flipped byte in the protected unread tail is rejected."""

        def change(root: Path) -> None:
            """Flip one byte of the protected unread tail."""
            path = root / RAW / "lab-guest.pcap"
            data = path.read_bytes()
            tail = bytes.fromhex(
                "0000012e00000004000000000000000800000008000100670002000a"
            )
            at = data.find(tail)
            assert at >= 0, "protected tail not found in the guest capture"
            raw = bytearray(data)
            raw[at + len(tail) - 1] ^= 1
            path.write_bytes(raw)

        self.mutate(change, "paired TCP bytes differ|Conflicting TCP retransmission")
