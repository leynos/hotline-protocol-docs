"""Fault controls for the portable A46/A48 settings persistence witness."""

import json
import re
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from protocol_capture import digest
from verify_native_settings_persistence import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Edit = cabc.Callable[[dict[str, typ.Any]], None]

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/native-settings-persistence-01"
)
LOGIN_PREFIX = "0000006b"  # a 107 request
FAULTS = {
    "legacy_count": "A46 legacy 64+2 count differs",
    "legacy_eof": "A46 legacy EOF actions differ",
    "legacy_frame": "Decoded frame mismatch",
    "old_source": "a46 source differs",
    "missing_a48_eof": "Owned socket EOFs differ",
    "fixed_login": "Prepared plan changed",
    "paired_pcap": "PCAP provenance differs",
    "stored_fork": "stored fork differs",
    "shutdown_cleanup": "User unit terminal state differs",
    "deadline": "Owned sockets/deadline differ",
    "drop": "Capture drops/primary zero differ",
    "missing_lock_deviation": "A48 lock deviation missing",
    "wrong_emulator": "Emulator identity differs",
    "wrong_shutdown_order": "Operator shutdown chronology differs",
}


def replace(path: Path, data: bytes) -> None:
    """Replace a file atomically with new bytes."""
    temporary = path.with_name(path.name + ".fault")
    temporary.write_bytes(data)
    temporary.replace(path)


def edit_json(path: Path, change: Edit) -> None:
    """Change the JSON of a file in place.

    Parameters
    ----------
    path : pathlib.Path
        The file.
    change : collections.abc.Callable[[dict[str, typing.Any]], None]
        The change to make to the parsed document.
    """
    value = json.loads(path.read_text())
    change(value)
    replace(path, (json.dumps(value, indent=2) + "\n").encode())


def resign(corpus: Path) -> None:
    """Record the new size and hash of every manifest file, and the checksum list."""
    manifest = json.loads((corpus / "manifest.json").read_text())
    for name in manifest["files"]:
        path = corpus / name
        manifest["files"][name] = {
            "bytes": path.stat().st_size,
            "sha256": digest(path.read_bytes()),
        }
    replace(corpus / "manifest.json", (json.dumps(manifest, indent=2) + "\n").encode())
    replace(
        corpus / "SHA256SUMS",
        "".join(
            f"{digest((corpus / name).read_bytes())}  {name}\n"
            for name in sorted(set(manifest["files"]) | {"manifest.json"})
        ).encode(),
    )


def nested_checksums(corpus: Path, phase: int) -> None:
    """Record the new hashes of a phase capture's plan and report."""
    case = "phase1" if phase == 1 else "phase2"
    directory = corpus / f"phase{phase}" / case
    replace(
        directory / "checksums.sha256",
        "".join(
            f"{digest((directory / name).read_bytes())}  {name}\n"
            for name in ("plan.json", "report.json")
        ).encode(),
    )


def flip_last_byte(path: Path) -> None:
    """Change the last byte of a file."""
    data = bytearray(path.read_bytes())
    data[-1] ^= 1
    replace(path, bytes(data))


def wrong_eof(data: dict[str, typ.Any]) -> None:
    """Move the legacy final EOF to the other connection."""
    next(e for e in data["events"] if e["event"] == "eof" and e["action"] == 65)[
        "connection"
    ] = "subject"


def missing_eof(data: dict[str, typ.Any]) -> None:
    """Drop the planned phase's final EOF event."""
    data["events"] = [
        e for e in data["events"] if not (e["event"] == "eof" and e["action"] == 27)
    ]


def wrong_login(data: dict[str, typ.Any]) -> None:
    """Change the last byte of the first fixed 107 login."""
    step = next(
        s
        for s in data["steps"]
        if s["op"] == "send" and s["hex"].startswith(LOGIN_PREFIX)
    )
    step["hex"] = step["hex"][:-2] + ("00" if step["hex"][-2:] != "00" else "01")


def fault_login(corpus: Path) -> None:
    """Change a fixed login in the planned phase and keep every pin consistent."""
    plan_path = corpus / "phase2/phase2/plan.json"
    edit_json(plan_path, wrong_login)
    plan_digest = digest(plan_path.read_bytes())
    edit_json(
        corpus / "phase2/phase2/report.json",
        lambda data: data.update(plan_sha256=plan_digest),
    )
    nested_checksums(corpus, 2)
    replace(corpus / "phase2/plans/phase2.json", plan_path.read_bytes())
    edit_json(
        corpus / "phase2/plans/source-hashes.json",
        lambda data: data.update(phase2=plan_digest),
    )


def edit_report(corpus: Path, phase: int, change: Edit) -> None:
    """Change a phase report and record the new checksums."""
    edit_json(corpus / f"phase{phase}/phase{phase}/report.json", change)
    nested_checksums(corpus, phase)


def edit_manifest(corpus: Path, change: Edit) -> None:
    """Change the manifest."""
    edit_json(corpus / "manifest.json", change)


def edit_timeline(corpus: Path) -> None:
    """Put the operator's absence after the capture stop."""
    edit_json(
        corpus / "baseline/operator-timeline.json",
        lambda data: data["phases"]["phase2"].update(
            operator_pid_absent_by_utc="2026-11-14T04:06:00+00:00"
        ),
    )


def apply_fault(corpus: Path, fault: str) -> None:
    """Inject one named fault into a copy of the corpus.

    Parameters
    ----------
    corpus : pathlib.Path
        The copy.
    fault : str
        A key of ``FAULTS``.
    """
    actions: dict[str, cabc.Callable[[], None]] = {
        "legacy_count": lambda: edit_report(
            corpus, 1, lambda data: data.update(completed_actions=65)
        ),
        "legacy_eof": lambda: edit_report(corpus, 1, wrong_eof),
        "legacy_frame": lambda: edit_report(
            corpus,
            1,
            lambda data: data["frames"][0].update(type=data["frames"][0]["type"] ^ 1),
        ),
        "old_source": lambda: replace(
            corpus / "source/a46/native_settings_persistence.py",
            (corpus / "source/a46/native_settings_persistence.py").read_bytes() + b"\n",
        ),
        "missing_a48_eof": lambda: edit_report(corpus, 2, missing_eof),
        "fixed_login": lambda: fault_login(corpus),
        "paired_pcap": lambda: flip_last_byte(corpus / "phase2/guest.pcap"),
        "stored_fork": lambda: flip_last_byte(corpus / "phase1/stopped-fork-11202.bin"),
        "shutdown_cleanup": lambda: replace(
            corpus / "phase2/user-units-terminal.txt",
            (corpus / "phase2/user-units-terminal.txt")
            .read_bytes()
            .replace(b"MainPID=0", b"MainPID=1", 1),
        ),
        "deadline": lambda: replace(
            corpus / "phase2/deadline.txt", b"2026-11-14T04:00:00Z\n"
        ),
        "drop": lambda: replace(
            corpus / "phase1/capture-journal.txt",
            (corpus / "phase1/capture-journal.txt")
            .read_bytes()
            .replace(b"0 packets dropped by kernel", b"1 packets dropped by kernel", 1),
        ),
        "missing_lock_deviation": lambda: edit_manifest(
            corpus, lambda data: data.update(phase2_oracle_lock_deviation="")
        ),
        "wrong_emulator": lambda: edit_json(
            corpus / "phase2/emulator-identity.json",
            lambda data: data.update(exe_sha256="0" * 64),
        ),
        "wrong_shutdown_order": lambda: edit_timeline(corpus),
    }
    actions[fault]()


class PersistenceWitnessTests:
    """Fault controls for the portable A46/A48 settings persistence witness."""

    def test_complete_corpus(self) -> None:
        """The retained corpus verifies as control-only."""
        assert verify(CORPUS)["status"] == "verified_control_only", "expected status"

    def test_fault_controls(self) -> None:
        """Each of the fourteen faults is rejected with its own message."""
        for fault, expected in FAULTS.items():
            with tempfile.TemporaryDirectory() as temporary:
                corpus = Path(temporary) / "corpus"
                shutil.copytree(CORPUS, corpus)
                apply_fault(corpus, fault)
                resign(corpus)
                with pytest.raises(ValueError, match=re.escape(expected)):
                    verify(corpus)
