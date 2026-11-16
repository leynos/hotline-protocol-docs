#!/usr/bin/env python3
"""Verify bounded 303 diagnostic examples against recorded native identities."""

import dataclasses as dc
import json
import sys
from pathlib import Path

from capture_acceptance import driver_is
from native_packet_evidence import reconcile
from native_wire_names import FIELD_USER_ID, TYPE_USER_LEFT
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_diagnostic_frames import (
    DENIED,
    EMPTY_SECTIONS,
    MISSING,
    NAMES,
    diagnostic_text,
    failure,
    sent,
    success,
    uid_field,
)
from verify_native_diagnostic_semantic import semantic
from verify_native_shx import sha

# The names below stay importable from this module. semantic is imported by
# test_native_diagnostics and the evidence checkers; the rest are the frame helpers,
# which the original module defined publicly.
__all__ = [
    "DENIED",
    "EMPTY_SECTIONS",
    "MISSING",
    "NAMES",
    "diagnostic_text",
    "failure",
    "main",
    "semantic",
    "sent",
    "show",
    "success",
    "uid_field",
    "verify",
]

EMULATOR_PID = 1259319  # the emulator process that ran the diagnostic corpus
EMULATOR_SHA256 = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
HOST_FRAMES = 125  # the host capture holds this many packets
PAIRED_LIFETIMES = 6  # the lifetimes that the reconciliation must pair


@dc.dataclass(frozen=True, slots=True)
class _Captures:
    """The inputs that every diagnostic report is checked against."""

    runtime: dict
    manifest: dict
    tails: dict
    host: list
    guest: list


def _check_inventory(directory: Path, manifest: dict) -> None:
    """Check that the manifest and the directory name the same reports.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict
        The parsed ``manifest.json``.
    """
    require(
        manifest["reports"] == list(NAMES)
        and {p.parent.name for p in directory.glob("*/report.json")} == set(NAMES),
        "Diagnostic report inventory differs",
    )


def _check_runtime(runtime: dict) -> None:
    """Check that the runtime names the emulator that ran the corpus.

    Parameters
    ----------
    runtime : dict
        The parsed ``runtime.json``.
    """
    require(
        runtime["emulator_pid"] == EMULATOR_PID
        and runtime["running_executable_sha256"] == EMULATOR_SHA256,
        "Diagnostic runtime identity differs",
    )


def _check_host_capture(directory: Path, host: list) -> None:
    """Check the packet count and the drop count of the host capture.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    host : list
        The packets of the host capture.
    """
    require(
        len(host) == HOST_FRAMES
        and "0 packets dropped by kernel"
        in (directory / "host-capture-statistics.txt").read_text(),
        "Diagnostic host capture count/drop differs",
    )


def _read_captures(
    directory: Path, runtime: dict, manifest: dict, tails: dict
) -> _Captures:
    """Read the host and guest captures and check the host capture.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    runtime : dict
        The parsed ``runtime.json``.
    manifest : dict
        The parsed ``manifest.json``.
    tails : dict
        The parsed ``unread-tails.json``.

    Returns
    -------
    _Captures
        The inputs that each report is checked with.
    """
    host = read_packets(directory / "host.pcap")
    guest = read_packets(directory / "guest.pcap")
    _check_host_capture(directory, host)
    return _Captures(runtime, manifest, tails, host, guest)


def _check_identity(path: Path, report: dict, captures: _Captures) -> None:
    """Check the oracle and plan identity of one diagnostic report.

    Parameters
    ----------
    path : pathlib.Path
        The directory of the report.
    report : dict
        The verified report.
    captures : _Captures
        The runtime and manifest that the plan and the report must name.
    """
    plan = json.loads((path / "plan.json").read_text())
    require(
        report["status"] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and plan["environment"] == captures.runtime
        and driver_is(report, captures.manifest["driver_sha256"]),
        "Diagnostic oracle/plan identity differs",
    )


def _reconcile_view(report: dict, captures: _Captures, name: str) -> int:
    """Reconcile one report with the captures and count its paired lifetimes.

    Parameters
    ----------
    report : dict
        The verified report.
    captures : _Captures
        The captures and the unread tails.
    name : str
        The name of the report, which keys its unread tails.

    Returns
    -------
    int
        The number of paired lifetimes.
    """
    view_tails = captures.tails.get(name, {})
    observations = reconcile(
        report,
        captures.host,
        captures.guest,
        unread_output={
            k: bytes.fromhex(v) for k, v in view_tails.get("host", {}).items()
        },
        guest_unread_output={
            k: bytes.fromhex(v) for k, v in view_tails.get("guest", {}).items()
        },
    )
    return len(observations)


def _verify_named(directory: Path, name: str, captures: _Captures) -> tuple[dict, int]:
    """Verify one diagnostic report and reconcile it.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    name : str
        The name of the report.
    captures : _Captures
        The captures and the unread tails.

    Returns
    -------
    tuple[dict, int]
        The verified report and its number of paired lifetimes.
    """
    path = directory / name
    report = verify_capture(path)
    _check_identity(path, report, captures)
    return report, _reconcile_view(report, captures, name)


def _verify_reports(directory: Path, captures: _Captures) -> tuple[dict, int]:
    """Verify every diagnostic report in the order of ``NAMES``.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    captures : _Captures
        The captures and the unread tails.

    Returns
    -------
    tuple[dict, int]
        The verified report of each case and the total number of paired lifetimes.
    """
    reports = {}
    paired = 0
    for name in NAMES:
        report, count = _verify_named(directory, name, captures)
        paired += count
        reports[name] = report
    return reports, paired


def _check_tail(tails: dict) -> None:
    """Check the unread owned departure tail of the observation.

    Parameters
    ----------
    tails : dict
        The parsed ``unread-tails.json``.
    """
    tail = bytes.fromhex(tails["observe"]["host"]["main"])
    require(
        tails["observe"]["guest"]["main"] == tail.hex()
        and decode_frame(tail)["type"] == TYPE_USER_LEFT
        and decode_frame(tail)["fields"] == [{"id": FIELD_USER_ID, "hex": "0090"}],
        "Unread owned departure tail differs",
    )


def verify(directory: Path) -> dict:
    """Verify a diagnostic corpus and return its summary.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict
        The number of completed reports, the paired connections and the semantic
        identities.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    _check_inventory(directory, manifest)
    runtime = json.loads((directory / "runtime.json").read_text())
    _check_runtime(runtime)
    tails = json.loads((directory / "unread-tails.json").read_text())
    captures = _read_captures(directory, runtime, manifest, tails)
    reports, paired = _verify_reports(directory, captures)
    _check_tail(tails)
    result = semantic(reports)
    require(paired == PAIRED_LIFETIMES, "Diagnostic paired lifetime count differs")
    require(
        sha(directory / "sources/native_diagnostic_cases.initial.py.txt")
        == manifest["initial_generator_sha256"],
        "Initial generated plan source differs",
    )
    return {"completed_reports": len(reports), "paired_connections": paired, **result}


def show(directory: str) -> None:
    """Print the JSON summary of the verification of the corpus in ``directory``.

    Parameters
    ----------
    directory : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(directory)), indent=2) + "\n")


def main() -> None:
    """Verify a diagnostic corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
