"""Check the stopped preparation, the emulator identity and the capture receipts.

The identity is the one that the retained runtime recorded: the process, its
image, its network namespace, the capture recorders and the managed lease.
"""

import datetime as dt
import typing as typ

from verify_native_liveness_checks import Report, need, read, utc
from verify_native_liveness_pins import (
    A7,
    BASE,
    DATA,
    DEADLINE,
    EXE,
    INODE,
    NS,
    PID,
    ROM,
    RSRC,
    START,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

HOST_NETNS_INODE = 4026531840  # the network namespace inode of the host
NAMESPACE_NETNS_INODE = 4026533605  # the network namespace inode of the lab
LOCK_FD = 3  # the descriptor that the managed lease holds
PLUS_SECONDS = 5  # the capture coverage that must extend past the deadline
ACTIVE_USERS = 2  # the number of allocated active users the HFS preflight records
ORIGINAL_TICKS = {"1099659": "767842", "1012834": "2357813"}


def _immutable(prep: Report, hfs: Report) -> bool:
    """Return whether the preparation and the immutable sources are as recorded.

    Parameters
    ----------
    prep : dict[str, typing.Any]
        The final preflight record.
    hfs : dict[str, typing.Any]
        The HFS preflight record.

    Returns
    -------
    bool
        Whether every recorded identity matches.
    """
    return (
        prep["prepared"]["base.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["sha256"] == BASE
        and prep["prepared"]["working.dsk"]["inode"] == INODE
        and prep["prepared"]["rom"]["sha256"] == ROM
        and prep["source_hashes_unchanged"]
        and hfs["banned_absent"]
        and len(hfs["allocated_active_users"]) == ACTIVE_USERS
        and all(item["matches"] and item["exit"] == 0 for item in hfs["files"].values())
        and hfs["files"]["server-data"]["sha256"] == DATA
        and hfs["files"]["server-rsrc"]["sha256"] == RSRC
    )


def _proof(proof: Report, runtime: Report) -> bool:
    """Return whether the emulator proof matches the pinned process and originals.

    Parameters
    ----------
    proof : dict[str, typing.Any]
        The actual emulator proof.
    runtime : dict[str, typing.Any]
        The runtime record.

    Returns
    -------
    bool
        Whether the process, image, namespace and originals match.
    """
    return (
        (proof["pid"], proof["starttime"], proof["netns"], proof["working_image_inode"])
        == (PID, START, NS, INODE)
        and proof["exe_sha256"] == EXE
        and proof["fd6"] == runtime["owned_working_image"]
        and proof["fd16"].endswith("native-liveness-epoch-01/lab-guest.pcap")
        and proof["original_startticks"] == ORIGINAL_TICKS
    )


def _receipt(runtime: Report, receipt: Report) -> bool:
    """Return whether the runtime and the capture receipt agree with the pins.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The runtime record.
    receipt : dict[str, typing.Any]
        The capture-ready receipt.

    Returns
    -------
    bool
        Whether the identity, the deadline and the receipt fields agree.
    """
    return (
        runtime["emulator_pid"] == receipt["emulator_pid"] == PID
        and runtime["emulator_starttime"] == receipt["emulator_starttime"] == START
        and runtime["emulator_sha256"] == receipt["emulator_sha256"] == EXE
        and runtime["emulator_netns"] == receipt["emulator_netns"] == NS
        and runtime["owned_working_image_inode"] == INODE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["source_a7_sha256"] == A7
        and receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and all(runtime[key] == receipt[key] for key in runtime)
    )


def _check_failure(raw: Path) -> None:
    """Check the retained unprivileged observer failure.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    """
    failure = read(raw / "capture-readiness-operator-error.json")
    need(
        failure["native_socket_actions"] == 0
        and "PermissionError" in failure["failure"]
        and (raw / "host-ready.uid1000-failed.stdout").stat().st_size == 0
        and (raw / "namespace-ready.uid1000-failed.stdout").stat().st_size == 0,
        "Retained unprivileged observer failure differs",
    )


def _check_recorder(raw: Path, receipt: Report, label: str) -> None:
    """Check the managed recorder of one capture side.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    label : str
        Either ``host`` or ``namespace``.
    """
    ready = read(raw / f"{label}-ready.json")
    meta = receipt["managed_capture"][label]
    netns = HOST_NETNS_INODE if label == "host" else NAMESPACE_NETNS_INODE
    need(
        ready == meta
        and ready["header24"].startswith("d4c3b2a1")
        and ready["pid"] == receipt[f"{label}_recorder_pid"]
        and ready["start_ticks"] == receipt[f"{label}_recorder_starttime"]
        and ready["fd"] >= 0
        and ready["inode"] > 0
        and ready["netns_inode"] == netns
        and ready["capture"] == receipt[f"{label}_pcap"]
        and ready["deadline_utc"] == DEADLINE
        and ready["unit_properties"]["ActiveState"] == "active"
        and ready["unit_properties"]["MainPID"] == str(ready["pid"])
        and ready["unit_properties"]["RuntimeMaxUSec"] == "15min"
        and ready["unit_properties"]["KillMode"] == "control-group",
        f"{label} managed recorder differs",
    )


def _check_coverage(raw: Path, receipt: Report) -> None:
    """Check the managed lease and the capture coverage past the deadline.

    Parameters
    ----------
    raw : pathlib.Path
        The raw evidence directory.
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    """
    coverage = read(raw / "independent-plus5-coverage.json")
    need(
        all(
            item["covers_plus5"]
            and utc(item["earliest_runtime_end_utc"])
            > utc(DEADLINE) + dt.timedelta(seconds=PLUS_SECONDS)
            for item in coverage.values()
        )
        and receipt["managed_lock"]["busy_exit"] == 1
        and receipt["managed_lock"]["fd"] == LOCK_FD
        and receipt["managed_lock"]["lock_inode"] > 0
        and receipt["managed_lock"]["unit_properties"]["MainPID"]
        == str(receipt["managed_lock"]["pid"])
        and receipt["managed_lock"]["unit_properties"]["ActiveState"] == "active",
        "Managed lease or +5 capture coverage differs",
    )


def identity(corpus: Path) -> Report:
    """Check the preparation, the emulator identity, the recorders and the lease.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The capture-ready receipt.
    """
    raw = corpus / "raw"
    prep = read(corpus / "preparation/final-preflight.json")
    hfs = read(corpus / "preparation/hfs-preflight.json")
    proof = read(raw / "actual-emulator-proof.json")
    runtime = read(raw / "runtime.json")
    receipt = read(raw / "capture-ready.json")
    need(_immutable(prep, hfs), "Stopped preparation or immutable source differs")
    need(
        _proof(proof, runtime),
        "Actual emulator/guest capture or originals differ",
    )
    need(
        _receipt(runtime, receipt),
        "As-run runtime or fixed deadline differs",
    )
    _check_failure(raw)
    for label in ("host", "namespace"):
        _check_recorder(raw, receipt, label)
    _check_coverage(raw, receipt)
    return receipt
