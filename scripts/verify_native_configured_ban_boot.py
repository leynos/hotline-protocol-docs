"""Check the lab emulator, the lease, the boot deadline and the unsaved UI rehearsal."""

import datetime as dt
import typing as typ

from verify_native_configured_ban_constants import (
    CAPTURE_WINDOW_SECONDS,
    CLIENT_PID,
    DISTINCT_NAMESPACES,
    EMPTY_PCAP_BYTES,
    EXE,
    LEASE_LOCK_INODE,
    LEASE_MAIN_PID,
    MIN_REMAINING_SECONDS,
    NS,
    PID,
    PRIMARY_PID,
    START,
)
from verify_native_configured_ban_support import Path, need, read, sha


def boot_and_ui(corpus: Path) -> dict:
    """Check the boot of the lab and the unsaved UI rehearsal in the retained case.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The readiness record of the boot.
    """
    root = corpus / "native-configured-apply-c66"
    ready, processes = read(root / "readiness.json"), read(root / "process-ready.json")
    _check_lab(ready, processes)
    _check_lease(root)
    deadline = read(root / "deadline.json")
    _check_deadline(root, ready, deadline)
    for label in ("host", "namespace"):
        _check_recorder(root, deadline, label)
    _check_ui(root, ready)
    return ready


def _check_lab(ready: dict[str, typ.Any], processes: dict[str, typ.Any]) -> None:
    """Check that the lab emulator is the original process in its namespace.

    Parameters
    ----------
    ready : dict[str, typing.Any]
        The readiness record of the boot.
    processes : dict[str, typing.Any]
        The process record of the lab, the primary server and the client.
    """
    lab = processes["lab"]
    need(
        ready["actual_emulator"] == lab
        and (lab["pid"], lab["starttime"], lab["netns"]) == (PID, START, NS)
        and lab["exe_sha256"] == EXE
        and lab["exe"].endswith(EXE)
        and lab["fd6"].endswith("native-configured-apply-01/working.dsk")
        and lab["fd16"].endswith("native-configured-apply-c66/lab-guest.pcap")
        and lab["uid"].split()[1] == "1000"
        and lab["cap_eff"].split()[1] == "0000000000020000"
        and processes["primary"]["pid"] == PRIMARY_PID
        and processes["client"]["pid"] == CLIENT_PID
        and len({
            lab["netns"],
            processes["primary"]["netns"],
            processes["client"]["netns"],
        })
        == DISTINCT_NAMESPACES,
        "Actual lab emulator or original identity differs",
    )


def _check_lease(root: Path) -> None:
    """Check the managed oracle lease that the case ran under.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    """
    lease = read(root / "lease-ready.json")
    need(
        lease["main_pid"] == LEASE_MAIN_PID
        and lease["lock_inode"] == LEASE_LOCK_INODE
        and lease["busy_flock_exit"] == 1
        and lease["uid"].split()[1] == "1000",
        "Managed oracle lockholder differs",
    )


def _check_deadline(
    root: Path, ready: dict[str, typ.Any], deadline: dict[str, typ.Any]
) -> None:
    """Check the boot deadline, the route table and the no-contact readiness.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    ready : dict[str, typing.Any]
        The readiness record of the boot.
    deadline : dict[str, typing.Any]
        The deadline record of the case.
    """
    fixed = dt.datetime.fromisoformat(deadline["fixed_deadline_utc"])
    plus = dt.datetime.fromisoformat(deadline["capture_deadline_utc"])
    need(
        (plus - fixed).total_seconds() == CAPTURE_WINDOW_SECONDS
        and ready["fixed_deadline_utc"] == deadline["fixed_deadline_utc"]
        and ready["remaining_seconds"] >= MIN_REMAINING_SECONDS
        and ready["namespace_established_connections"] == 0
        and ready["namespace_routes"] == []
        and read(root / "namespace-routes.json") == []
        and not (root / "namespace-established.txt").read_text(),
        "Boot deadline, route or no-contact UI readiness differs",
    )


def _check_recorder(root: Path, deadline: dict[str, typ.Any], label: str) -> None:
    """Check the identity and the deadline of one packet recorder.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    deadline : dict[str, typing.Any]
        The deadline record of the case.
    label : str
        The recorder: ``host`` or ``namespace``.
    """
    first = read(root / f"{label}-ready.json")
    final = read(root / f"{label}-ready-final.json")
    case = read(root / f"{label}-ready-case.json")
    need(
        first["pid"] == final["pid"] == case["pid"]
        and first["start_ticks"] == final["start_ticks"] == case["start_ticks"]
        and first["header24"] == final["header24"] == case["header24"]
        and all(
            x["deadline_utc"] == deadline["capture_deadline_utc"]
            for x in (first, final, case)
        )
        and all(
            x["unit_properties"]["ActiveState"] == "active"
            for x in (first, final, case)
        )
        and all(
            x["unit_properties"]["KillMode"] == "control-group"
            for x in (first, final, case)
        ),
        f"{label} recorder identity or deadline differs",
    )


def _check_ui(root: Path, ready: dict[str, typ.Any]) -> None:
    """Check the screenshots and the unsaved UI rehearsal of the boot.

    Parameters
    ----------
    root : pathlib.Path
        The retained case directory.
    ready : dict[str, typing.Any]
        The readiness record of the boot.
    """
    for name, expected in ready["screenshots_sha256"].items():
        need(sha(root / name) == expected, f"{name} UI screenshot differs")
    need(
        ready["ban_ui_empty_before_entry"] is True
        and ready["typed_ip"] == "10.0.2.2"
        and ready["info_empty"] is True
        and ready["clicked_cancel_without_add_save"] is True
        and ready["host_primary_pcap_bytes"] == EMPTY_PCAP_BYTES
        and (root / "options-cancel.utc").exists(),
        "Unsaved UI rehearsal differs",
    )
