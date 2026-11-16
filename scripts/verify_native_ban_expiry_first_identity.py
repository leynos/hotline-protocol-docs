"""Check the emulator, recorder and terminal receipts of the first ban epoch."""

import re
import typing as typ

from verify_native_ban_expiry_first_common import need, read, when
from verify_native_ban_expiry_first_wire import (
    A7,
    DEADLINE,
    EXE,
    HOST_RECORDER_PID,
    INODE,
    LOCK_FD,
    LOCK_INODE,
    LOCK_PID,
    NAMESPACE_RECORDER_PID,
    NS,
    NS_INODE,
    PID,
    START,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def identity_gate(corpus: Path, raw: Path) -> dict:
    """Check the identity, recorder and terminal receipts of the first epoch.

    Parameters
    ----------
    corpus : Path
        The corpus directory, which the checks do not read.
    raw : Path
        The raw receipts directory.

    Returns
    -------
    dict
        The capture readiness receipt of the epoch.
    """
    receipt = read(raw / "capture-ready.json")
    runtime = read(raw / "runtime-asrun.json")
    preboot = read(raw / "preboot.json")
    terminal = read(raw / "first-terminal.json")
    emulator_gate(receipt, runtime, preboot)
    recorder_gate(receipt)
    capture_gate(receipt)
    terminal_gate(raw, terminal)
    cleanup_gate(raw)
    return receipt


def emulator_gate(receipt: dict, runtime: dict, preboot: dict) -> None:
    """Check that the epoch ran the expected emulator, image and deadline.

    Parameters
    ----------
    receipt : dict
        The capture readiness receipt.
    runtime : dict
        The as-run runtime record, which must agree with the receipt.
    preboot : dict
        The preboot record of the owned working image.
    """
    need(
        receipt["fixture_profile"] == "control-only"
        and receipt["full_file_baseline"] == "not_exercised"
        and receipt["source_a7_sha256"] == A7
        and receipt["emulator_pid"] == PID
        and receipt["emulator_starttime"] == START
        and receipt["emulator_netns"] == NS
        and receipt["emulator_netns_inode"] == NS_INODE
        and receipt["owned_working_image_inode"] == INODE
        and receipt["emulator_sha256"] == EXE
        and receipt["deadline_utc"] == DEADLINE
        and receipt["epoch_started_utc"] == "2026-11-14T05:44:51+00:00"
        and all(runtime[k] == receipt[k] for k in runtime)
        and preboot["image_inode"] == INODE
        and preboot["fixed_deadline_utc"] == DEADLINE,
        "Actual emulator identity, profile or deadline differs",
    )


def recorder_gate(receipt: dict) -> None:
    """Check the recorders and the managed capture lock of the epoch.

    Parameters
    ----------
    receipt : dict
        The capture readiness receipt.
    """
    need(
        receipt["ns_routes"] == []
        and receipt["primary_syn_count"] == 0
        and receipt["host_recorder_pid"] == HOST_RECORDER_PID
        and receipt["namespace_recorder_pid"] == NAMESPACE_RECORDER_PID
        and receipt["managed_lock"]["pid"] == LOCK_PID
        and receipt["managed_lock"]["fd"] == LOCK_FD
        and receipt["managed_lock"]["busy_exit"] == 1
        and receipt["managed_lock"]["lock_inode"] == LOCK_INODE,
        "Managed recorder or lock receipt differs",
    )


def capture_gate(receipt: dict) -> None:
    """Check the readiness of the host and namespace captures.

    Parameters
    ----------
    receipt : dict
        The capture readiness receipt.
    """
    for label in ("host", "namespace"):
        meta = receipt["managed_capture"][label]
        need(
            meta["unit_properties"]["ActiveState"] == "active"
            and meta["unit_properties"]["KillMode"] == "control-group"
            and meta["unit_properties"]["RuntimeMaxUSec"] == "15min"
            and meta["deadline_utc"] == DEADLINE
            and meta["pid"] == receipt[f"{label}_recorder_pid"]
            and meta["header24"].startswith("d4c3b2a1"),
            f"{label} capture readiness differs",
        )


def terminal_gate(raw: Path, terminal: dict) -> None:
    """Check the terminal receipt of the first epoch against its deadline.

    Parameters
    ----------
    raw : Path
        The raw receipts directory, which holds the exit record.
    terminal : dict
        The first-epoch terminal receipt.
    """
    need(
        terminal["first_exit"] == 0
        and terminal["actual_emulator_pid"] == PID
        and terminal["image_inode"] == INODE
        and terminal["vm_retained_for_idle"] is True
        and terminal["application_sockets_established"] is False
        and terminal["oracle_mutex_free"] is True
        and terminal["original_pids_stable"] is True
        and terminal["primary_syn_count"] == 0
        and when(terminal["utc"]) < when(DEADLINE)
        and (raw / "c77-first.exit").read_text() == "0\n",
        "First-epoch terminal receipt differs",
    )


def cleanup_gate(raw: Path) -> None:
    """Check that the capture logs and the owned units were cleaned up.

    Parameters
    ----------
    raw : Path
        The raw receipts directory.
    """
    need(
        all(
            re.search(
                r"0 packets dropped by kernel",
                (raw / f"{name}-terminal-journal.log").read_text(),
            )
            for name in ("host", "namespace")
        )
        and "0 packets captured" in (raw / "host-terminal-journal.log").read_text()
        and all(
            f"Id=mothra-native-expiry-c75-{name}.service\nActiveState=inactive\nSubState=dead\nMainPID=0\nResult=success"
            in (raw / "c75-capture-lock-terminal.txt").read_text()
            for name in ("host", "namespace", "lease")
        ),
        "Capture drop or owned cleanup differs",
    )
