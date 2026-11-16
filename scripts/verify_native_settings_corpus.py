"""Replay the frozen C26 native settings corpus without a running Mac guest."""

import json
import sys
from pathlib import Path

from pcap_tcp import read_packets
from pinned_source import pinned_bytes
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_settings import semantic
from verify_native_settings import verify as verify_cases
from verify_native_settings_a7 import a7_semantics
from verify_native_settings_core import ORACLE_SHA, Report, reply, sha, values
from verify_native_settings_packets import a7_packets, case_packets

# The checks of the A7 baseline, the packet reconciliation and the shared readers
# live in verify_native_settings_a7, _packets and _core. The names that this module
# defined before they moved stay importable from here.
__all__ = [
    "RAW_INDEX_SHA",
    "a7_packets",
    "a7_semantics",
    "case_packets",
    "inventory",
    "main",
    "reply",
    "sha",
    "values",
    "verify",
]

RAW_INDEX_SHA = "f953f1146d5f89da3d33d1310c2364a56847514b23a9751daf0ceb2d2faa9b58"
CASE_COUNT = 10
RAW_FILE_COUNT = 73
SOURCE_NAMES = (
    "native_settings_cases.py",
    "verify_native_settings.py",
    "protocol_capture.py",
)
RECORDER_PACKETS = "3754 packets captured"
RECORDER_NO_DROPS = "0 packets dropped by kernel"


def read_index(raw: Path, manifest: Report) -> dict[str, str]:
    """Check the identity of the raw inventory and read it.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.

    Returns
    -------
    dict[str, str]
        The digest of each listed file, by name.
    """
    index = raw / "SHA256SUMS"
    require(
        sha(index.read_bytes()) == RAW_INDEX_SHA == manifest["raw_sha256sums_sha256"],
        "Frozen raw inventory identity differs",
    )
    entries: dict[str, str] = {}
    for line in index.read_text().splitlines():
        digest, name = line.split("  ", 1)
        require(
            name not in entries
            and not Path(name).is_absolute()
            and ".." not in Path(name).parts,
            "Unsafe raw inventory path",
        )
        entries[name] = digest
    return entries


def inventory(raw: Path, manifest: Report) -> None:
    """Check the frozen raw inventory against the files on disk.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    """
    entries = read_index(raw, manifest)
    require(
        set(entries)
        == {str(p.relative_to(raw)) for p in raw.rglob("*") if p.is_file()}
        - {"SHA256SUMS"},
        "Raw inventory coverage differs",
    )
    require(
        len(entries) + 1 == RAW_FILE_COUNT == manifest["raw_file_count"],
        "Raw file count differs",
    )
    for name, digest in entries.items():
        require(
            sha((raw / name).read_bytes()) == digest, f"Raw file hash differs: {name}"
        )


def check_capture_sources(raw: Path) -> None:
    """Compare the sources recorded at capture with their pinned bytes.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    """
    recorded = {
        Path(line.split()[1]).name: line.split()[0]
        for line in (raw / "source-hashes.txt").read_text().splitlines()[1:]
    }
    for name in SOURCE_NAMES:
        require(
            sha(pinned_bytes(name)) == recorded[name],
            f"Capture source differs: {name}",
        )


def check_case_semantics(raw: Path) -> None:
    """Re-read the semantics of every case against its own expectation.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    """
    for case in (raw / "cases").iterdir():
        if case.is_dir():
            plan = json.loads((case / "plan.json").read_text())
            semantic(
                json.loads((case / "report.json").read_text()), plan["expectation"]
            )


def phase_baseline(raw: Path, phase: str, source: Report) -> tuple[Report, int]:
    """Check one A7 baseline phase, its capture and its packets.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    phase : str
        ``preflight`` or ``postflight``.
    source : dict[str, typing.Any]
        The A7 source plan, whose steps the phase's plan repeats.

    Returns
    -------
    tuple[dict[str, typing.Any], int]
        The phase's A7 semantics and the number of paired sockets.
    """
    path = raw / phase
    plan = json.loads((path / "capture/plan.json").read_text())
    require(plan["steps"] == source["steps"], f"A7 {phase} immutable steps differ")
    baseline = a7_semantics(json.loads((path / "capture/report.json").read_text()))
    report = verify_capture(path / "capture")
    paired = a7_packets(
        report,
        read_packets(path / "host.pcap"),
        read_packets(path / "guest-cumulative.pcap"),
    )
    return baseline, paired


def check_recorder(raw: Path) -> None:
    """Check the recorder's packet counters and its terminal status.

    Parameters
    ----------
    raw : pathlib.Path
        The corpus's ``raw`` directory.
    """
    require(
        RECORDER_PACKETS in (raw / "recorder.log").read_text()
        and RECORDER_NO_DROPS in (raw / "recorder.log").read_text(),
        "Recorder counters differ",
    )
    require(
        "Result=success" in (raw / "recorder-terminal.txt").read_text()
        and "ExecMainStatus=0" in (raw / "recorder-terminal.txt").read_text(),
        "Recorder terminal status differs",
    )


def verify(bundle: Path) -> Report:
    """Replay the whole corpus offline.

    Parameters
    ----------
    bundle : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The status, the case results, the A7 baselines and the paired sockets.
    """
    raw = bundle / "raw"
    manifest = json.loads((bundle / "manifest.json").read_text())
    require(
        manifest["oracle_sha256"] == ORACLE_SHA
        and manifest["case_count"] == CASE_COUNT,
        "Manifest oracle/case identity differs",
    )
    source = json.loads((raw / "source/a7-plan.json").read_text())
    check_capture_sources(raw)
    check_case_semantics(raw)
    results = verify_cases(raw / "cases")["cases"]
    host = read_packets(raw / "host.pcap")
    guest = read_packets(raw / "postflight/guest-cumulative.pcap")
    paired = case_packets(raw, results, host, guest)
    baselines = {}
    for phase in ("preflight", "postflight"):
        baselines[phase], phase_paired = phase_baseline(raw, phase, source)
        paired += phase_paired
    check_recorder(raw)
    inventory(raw, manifest)
    return {
        "status": "verified",
        "cases": results,
        "a7": baselines,
        "paired_sockets": paired,
    }


def show(bundle: str) -> None:
    """Print the JSON result of replaying a corpus.

    Parameters
    ----------
    bundle
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(bundle)), indent=2) + "\n")


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(show, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
