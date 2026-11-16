"""The live-host and plan gates of the isolated ban-control capture.

Part of the capture driver's module set (``native_control_readiness.CAPTURE_MODULES``).
These gates read ``/proc`` and the recorders' capture files, so they run only on
the host that holds the emulator, and only as root.
"""

import json
import os
import typing as typ
from pathlib import Path

import native_ban_control_cases as cases
from protocol_capture import digest, validate_plan
from verify_native_core import require

type Receipt = dict[str, typ.Any]

PCAP_MAGICS = (
    bytes.fromhex("d4c3b2a1"),
    bytes.fromhex("a1b2c3d4"),
    bytes.fromhex("4d3cb2a1"),
)
PCAP_HEADER_BYTES = 24  # a capture file of no packets is only its header
STAT_START_FIELD = 19  # the start time, counted after the command's closing bracket
EMULATOR_IMAGE_FD = 6  # the descriptor that holds the owned working image
PLAN_NAMES = ("readiness", "guard", "seed", "ban", "probe")
FORBIDDEN_PORTS = {15500, 15501}  # the primary server's own endpoints
CONTROL_HOST = "127.0.0.1"

__all__ = ["capture_gate", "plan_gate", "require_controller_uid"]


def _start_time(proc: Path) -> str:
    """Read a process's start time from its ``stat`` file.

    Parameters
    ----------
    proc : pathlib.Path
        The process's ``/proc`` directory.

    Returns
    -------
    str
        The start time, in clock ticks since boot.
    """
    text = (proc / "stat").read_text()
    return text.rsplit(") ", 1)[1].split()[STAT_START_FIELD]


def _pcaps(receipt: Receipt) -> None:
    """Check that each recorder's capture file is ready and the host's is empty.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    """
    for label in ("host", "namespace", "guest"):
        path = Path(receipt[f"{label}_pcap"])
        with path.open("rb") as handle:
            header = handle.read(PCAP_HEADER_BYTES)
        require(header[:4] in PCAP_MAGICS, f"{label} capture not ready")
        if label == "host":
            require(
                path.stat().st_size == PCAP_HEADER_BYTES,
                "Primary SYN recorder is nonempty",
            )


def _recorders(receipt: Receipt) -> None:
    """Check that each recorder still runs under the recorded PID and start time.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    """
    for label in ("host", "namespace"):
        pid = receipt[f"{label}_recorder_pid"]
        require(Path(f"/proc/{pid}").exists(), f"{label} recorder absent")
        start = _start_time(Path(f"/proc/{pid}"))
        require(
            start == str(receipt[f"{label}_recorder_starttime"]),
            f"{label} recorder PID reused",
        )


def _emulator(receipt: Receipt) -> None:
    """Check the emulator's PID, start time, executable, image and namespace.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    """
    proc = Path(f"/proc/{receipt['emulator_pid']}")
    require(proc.exists(), "Actual lab emulator absent")
    require(
        _start_time(proc) == str(receipt["emulator_starttime"]), "Emulator PID reused"
    )
    require(
        digest((proc / "exe").read_bytes()) == receipt["emulator_sha256"]
        and os.readlink(proc / f"fd/{EMULATOR_IMAGE_FD}")  # ruff: ignore[os-readlink]  # compared as the kernel spells the link, not as a normalised path
        == receipt["owned_working_image"]
        and os.readlink(proc / "ns/net")  # ruff: ignore[os-readlink]  # as above
        == receipt["emulator_netns"],
        "Emulator executable, image or namespace changed",
    )


def capture_gate(receipt: Receipt) -> None:
    """Check that the recorders and the emulator are the ones that were recorded.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    """
    require(
        receipt["primary_syn_count"] == 0 and receipt["ns_routes"] == [],
        "Primary contact or external route",
    )
    _pcaps(receipt)
    _recorders(receipt)
    _emulator(receipt)


def require_controller_uid() -> None:
    """Refuse to go on unless the process is root.

    Raises
    ------
    PermissionError
        If the effective user is not root, which cannot inspect ``/proc``.
    """
    if os.geteuid() != 0:
        message = "Live coordinator requires root to inspect emulator /proc identity"
        raise PermissionError(message)


def _plan_identity(plan: dict[str, typ.Any], emulator_pid: int) -> None:
    """Check a plan's environment and control endpoint.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        A validated plan.
    emulator_pid : int
        The emulator's PID.
    """
    env = plan["environment"]
    require(
        env.get("emulator_pid") == emulator_pid
        and env.get("source_a7_sha256") == cases.A7_SHA
        and env.get("fixture_profile") == "control-only"
        and env.get("full_file_baseline") == "not_exercised"
        and plan["endpoints"]["control"]["host"] == CONTROL_HOST
        and plan["endpoints"]["control"]["port"] not in FORBIDDEN_PORTS,
        "Plan identity, profile or endpoint differs",
    )


def plan_gate(directory: Path, emulator_pid: int) -> None:
    """Check that the five plans are the ones the planner hashed.

    Parameters
    ----------
    directory : pathlib.Path
        The plan directory, with ``source-hashes.json``.
    emulator_pid : int
        The emulator's PID, which every plan must name.
    """
    hashes = json.loads((directory / "source-hashes.json").read_text())
    require(set(hashes) == set(PLAN_NAMES), "Plan inventory differs")
    for name in PLAN_NAMES:
        source = (directory / f"{name}.json").read_bytes()
        require(digest(source) == hashes[name], f"{name} source plan changed")
        plan = json.loads(source)
        validate_plan(plan)
        _plan_identity(plan, emulator_pid)
