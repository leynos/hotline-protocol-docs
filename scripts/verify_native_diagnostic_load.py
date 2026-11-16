#!/usr/bin/env python3
"""Verify a failed native 303 load attempt and exact owned-file cleanup."""

import datetime as dt
import hashlib
import json
import sys
from pathlib import Path

from native_packet_evidence import reconcile
from pcap_tcp import TCP_RST, direction, lifetime, read_packets, stream
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_diagnostic_load_frames import (
    CASES,
    current_uid,
    reply,
    sent,
)
from verify_native_diagnostic_load_semantic import semantic

# The names below stay importable from this module. The frame lookups live in
# verify_native_diagnostic_load_frames, and the checks in
# verify_native_diagnostic_load_semantic.
__all__ = [
    "CASES",
    "current_uid",
    "main",
    "packet_evidence",
    "reply",
    "semantic",
    "sent",
    "show",
    "verify",
]

HOST_SERVER_PORT = 15501  # the server port of the upload in the host capture
GUEST_SERVER_PORT = 5501  # the server port of the upload in the guest capture


def _reconcile_cases(directory: Path, reports: dict, guest: list) -> dict:
    """Reconcile the preflight and cleanup captures with the guest capture.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    reports : dict
        The verified report of each case.
    guest : list
        The packets of the guest capture after cleanup.

    Returns
    -------
    dict
        The reconciled observations, keyed by case name.
    """
    result = {}
    for name in ("preflight", "cleanup"):
        host = read_packets(directory / f"host-{name}.pcap")
        result[name] = reconcile(reports[name], host, guest)
    return result


def _seed_control(seed: dict, host: list, guest: list) -> dict:
    """Reconcile the seed's first connection as the control of the upload.

    Parameters
    ----------
    seed : dict
        The verified seed report.
    host : list
        The packets of the host seed capture.
    guest : list
        The packets of the guest capture after cleanup.

    Returns
    -------
    dict
        The reconciled observations of the control connection.
    """
    control = dict(seed)
    control["events"] = [e for e in seed["events"] if e["connection"] == "a"]
    control["streams"] = {"a": seed["streams"]["a"]}
    return reconcile(control, host, guest)


def _upload_connect(seed: dict) -> dict:
    """Return the connect event of the upload connection.

    Parameters
    ----------
    seed : dict
        The verified seed report.

    Returns
    -------
    dict
        The connect event.
    """
    return next(
        e
        for e in seed["events"]
        if e["event"] == "connect" and e["connection"] == "upload"
    )


def _start_us(seed: dict, connect: dict) -> int:
    """Return the start of the upload lifetime in microseconds.

    Parameters
    ----------
    seed : dict
        The verified seed report.
    connect : dict
        The connect event of the upload connection.

    Returns
    -------
    int
        The start time in microseconds since the epoch.
    """
    return int(
        dt.datetime.fromisoformat(seed["started_at_utc"]).timestamp() * 1e6
        + connect["elapsed_ns"] / 1000
    )


def _side_delivery(label: str, packets: list, ends: tuple, timing: tuple) -> int:
    """Measure the upload bytes that one capture delivered.

    Parameters
    ----------
    label : str
        The capture side, ``host`` or ``guest``.
    packets : list
        The packets of that capture.
    ends : tuple
        The client and the server endpoint of the upload on that capture.
    timing : tuple
        The verified seed report and the connect event of the upload.

    Returns
    -------
    int
        The number of uploaded bytes that the capture delivered.
    """
    client, server = ends
    seed, connect = timing
    recorded = bytes.fromhex(seed["streams"]["upload"]["sent_hex"])
    scoped = lifetime(packets, client, server, _start_us(seed, connect))
    prefix = stream(scoped, client, server)
    require(
        recorded.startswith(prefix) and len(prefix) < len(recorded),
        f"Seed {label} delivery was mislabelled complete",
    )
    require(stream(scoped, server, client) == b"", "Unexpected upload output")
    if label == "host":
        resets = [p for p in direction(scoped, server, client) if p["flags"] & TCP_RST]
        require(len(resets) >= 1, "Host did not retain server-side reset")
    return len(prefix)


def _seed_upload(seed: dict, host: list, guest: list) -> dict:
    """Measure the upload that the seed delivered on each side.

    Parameters
    ----------
    seed : dict
        The verified seed report.
    host : list
        The packets of the host seed capture.
    guest : list
        The packets of the guest capture after cleanup.

    Returns
    -------
    dict
        The number of bytes recorded and delivered on each side.
    """
    connect = _upload_connect(seed)
    port = connect["local_address"][1]
    recorded = bytes.fromhex(seed["streams"]["upload"]["sent_hex"])
    lengths = {
        "host": _side_delivery(
            "host",
            host,
            (("127.0.0.1", port), ("127.0.0.1", HOST_SERVER_PORT)),
            (seed, connect),
        ),
        "guest": _side_delivery(
            "guest",
            guest,
            (("10.0.2.2", port), ("10.0.2.15", GUEST_SERVER_PORT)),
            (seed, connect),
        ),
    }
    require(
        0 < lengths["guest"] < lengths["host"] < len(recorded),
        "Failure prefix ordering differs",
    )
    return {
        "recorder_sent_bytes": len(recorded),
        "host_delivered_bytes": lengths["host"],
        "guest_delivered_bytes": lengths["guest"],
    }


def packet_evidence(directory: Path, reports: dict[str, dict]) -> dict:
    """Reconcile the packet captures of the load attempt with its reports.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    reports : dict[str, dict]
        The verified report of each case, keyed by case name.

    Returns
    -------
    dict
        The reconciled observations and the seed upload byte counts.
    """
    guest = read_packets(directory / "guest-after-cleanup.pcap")
    result = _reconcile_cases(directory, reports, guest)
    seed = reports["seed"]
    host = read_packets(directory / "host-seed.pcap")
    result["seed_control"] = _seed_control(seed, host, guest)
    result["seed_upload"] = _seed_upload(seed, host, guest)
    return result


def _check_source(directory: Path, manifest: dict) -> None:
    """Check that the captured cleanup coordinator source is the one hashed.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict
        The parsed ``manifest.json``.
    """
    as_run = directory / "as-run-native_diagnostic_load_cases.py"
    require(
        hashlib.sha256(as_run.read_bytes()).hexdigest()
        == manifest["cleanup_driver_sha256"],
        "Captured cleanup coordinator source is missing or changed",
    )


def _load_reports(directory: Path) -> dict[str, dict]:
    """Verify the capture of each case and name its plan.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, dict]
        The verified report of each case, keyed by case name.
    """
    reports = {name: verify_capture(directory / name) for name in CASES}
    for name, report in reports.items():
        report["_plan_path"] = directory / name / "plan.json"
        require(report["profile"] == "native-mac-oracle", "Wrong capture profile")
    return reports


def verify(directory: Path) -> dict:
    """Verify a failed load attempt and its cleanup, and return the summary.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict
        The semantic identities and the packet evidence.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "Oracle identity differs")
    _check_source(directory, manifest)
    reports = _load_reports(directory)
    require(
        reports["cleanup"]["driver_sha256"] == manifest["cleanup_driver_sha256"],
        "Cleanup report does not identify its as-run source",
    )
    return {
        "semantic": semantic(reports),
        "packets": packet_evidence(directory, reports),
    }


def show(directory: str) -> None:
    """Print the JSON summary of the verification of the corpus in ``directory``.

    Parameters
    ----------
    directory : str
        The corpus directory.
    """
    sys.stdout.write(json.dumps(verify(Path(directory)), indent=2) + "\n")


def main() -> None:
    """Verify a failed native 303 load attempt from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
