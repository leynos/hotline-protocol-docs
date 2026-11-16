"""Re-read the live runtime of a ban-expiry epoch before any case runs.

Part of the ban-expiry controller (``native_ban_expiry_control``), which
re-exports every public name below. The gates read ``/proc``, ``systemctl`` and
``flock`` and fail closed with a ``ValueError`` when the runtime is not the one
the receipt names. Each check is made in the order listed in
:func:`runtime_gate`, so a fault is reported by the first check that finds it.
"""

import datetime as dt
import json
import os
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # runs systemctl, nsenter and flock with fixed argv, no shell
import time
from pathlib import Path

from native_ban_expiry_control_core import (
    Report,
    capture_window_bounds,
    require,
    runtime_cap_seconds,
    utc,
)
from native_control_readiness import capture_gate

DEFAULT_SERVICE_SECONDS = 900
UNIT_PROPERTIES = (
    "ActiveState,SubState,MainPID,RuntimeMaxUSec,ActiveEnterTimestampMonotonic,KillMode"
)
MICROSECONDS = 1_000_000
EXPIRY_MARGIN_US = 5_000_000
MIN_DEADLINE_SECONDS = 10
NSENTER_TIMEOUT_SECONDS = 5
GUEST_PCAP_FD = 16
FLAGS_BASE = 8
BUSY_EXIT = 1
RUNTIME_KEYS = (
    "emulator_pid",
    "emulator_starttime",
    "emulator_sha256",
    "emulator_netns_inode",
    "owned_working_image",
    "owned_working_image_inode",
)
NSENTER_TAIL = ("-n", "/usr/sbin/ip", "-j")


def live_service(
    meta: Report,
    deadline_utc: dt.datetime,
    service_seconds: int = DEFAULT_SERVICE_SECONDS,
) -> None:
    """Re-read a managed unit and require that it outlives the epoch deadline.

    Parameters
    ----------
    meta : dict[str, typing.Any]
        The unit as the runtime receipt recorded it.
    deadline_utc : datetime.datetime
        The deadline of the epoch.
    service_seconds : int
        The runtime cap the unit must carry.
    """
    unit = meta["unit"]
    require(
        unit.startswith("mothra-") and unit.endswith(".service"),
        "Unexpected managed unit",
    )
    command = [
        "systemctl",
        "show",
        unit,
        "--no-pager",
        f"--property={UNIT_PROPERTIES}",
    ]
    output = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        command,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    actual = dict(line.split("=", 1) for line in output.splitlines() if "=" in line)
    require(
        actual == meta["unit_properties"]
        and actual["ActiveState"] == "active"
        and actual["SubState"] == "running"
        and actual["MainPID"] == str(meta["pid"])
        and actual["KillMode"] == "control-group"
        and runtime_cap_seconds(actual["RuntimeMaxUSec"]) == service_seconds,
        "Managed service changed",
    )
    remaining_us = (
        deadline_utc - dt.datetime.now(dt.UTC)
    ).total_seconds() * MICROSECONDS
    expiry = (
        int(actual["ActiveEnterTimestampMonotonic"]) + service_seconds * MICROSECONDS
    )
    require(
        expiry - time.monotonic_ns() // 1000 >= remaining_us + EXPIRY_MARGIN_US,
        "Managed service expires before epoch deadline",
    )


def _ip_json(prefix: list[str], *query: str) -> list[Report]:
    """Run ``ip -j`` in the recorder's namespace and parse its output.

    Returns
    -------
    list[dict[str, typing.Any]]
        The parsed JSON list.
    """
    return json.loads(
        subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
            [*prefix, *query],
            capture_output=True,
            text=True,
            check=True,
            timeout=NSENTER_TIMEOUT_SECONDS,
        ).stdout
    )


def namespace_gate(receipt: Report) -> None:
    """Re-read recorder placement and routes in its actual network namespace."""
    recorder_pid = receipt["namespace_recorder_pid"]
    emulator_pid = receipt["emulator_pid"]
    expected = receipt["emulator_netns_inode"]
    require(
        os.stat(f"/proc/{recorder_pid}/ns/net").st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == os.stat(f"/proc/{emulator_pid}/ns/net").st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == expected,
        "Namespace recorder is not in the emulator namespace",
    )
    prefix = ["/usr/sbin/nsenter", "-t", str(recorder_pid), *NSENTER_TAIL]
    for family in ("-4", "-6"):
        routes = _ip_json(prefix, family, "route", "show", "table", "main")
        require(routes == [], f"Live {family} namespace routes changed")
    links = _ip_json(prefix, "link", "show")
    require(
        [link["ifname"] for link in links] == ["lo"],
        "Live namespace has a non-loopback interface",
    )


def _bound_to_plan(receipt: Report, env: Report) -> None:
    """Require the receipt to describe the process the plan was made for."""
    require(os.geteuid() == 0, "Live runner requires root for /proc identity")
    require(
        all(receipt[key] == env[key] for key in RUNTIME_KEYS),
        "Runtime receipt differs from plan",
    )
    require(
        os.stat("/proc/self/ns/net").st_ino  # ruff: ignore[os-stat]  # /proc identity; the tests substitute os.stat
        == receipt["emulator_netns_inode"],
        "Runner is not in the emulator network namespace",
    )


def _recorder_unit(
    receipt: Report, label: str, deadline_utc: dt.datetime, service_seconds: int
) -> None:
    """Require one managed recorder to be live, writable and unchanged."""
    meta = receipt["managed_capture"][label]
    props = meta["unit_properties"]
    require(
        meta["pid"] == receipt[f"{label}_recorder_pid"]
        and meta["deadline_utc"] == deadline_utc.isoformat()
        and meta["fd"] >= 0
        and props["MainPID"] == str(meta["pid"])
        and props["ActiveState"] == "active"
        and runtime_cap_seconds(props["RuntimeMaxUSec"]) == service_seconds
        and props["KillMode"] == "control-group",
        "Managed recorder receipt differs",
    )
    live_service(meta, deadline_utc, service_seconds)
    capture = Path(receipt[f"{label}_pcap"])
    fd = Path(f"/proc/{meta['pid']}/fd/{meta['fd']}")
    require(
        fd.stat().st_ino == capture.stat().st_ino
        and fd.stat().st_dev == capture.stat().st_dev,
        "Managed recorder lost writable capture FD",
    )
    fdinfo = Path(f"/proc/{meta['pid']}/fdinfo/{meta['fd']}")
    info = fdinfo.read_text(encoding="utf-8").splitlines()
    flags = int(
        next(line.split()[1] for line in info if line.startswith("flags:")),
        FLAGS_BASE,
    )
    require(
        flags & os.O_ACCMODE in {os.O_WRONLY, os.O_RDWR},
        "Capture FD is not writable",
    )


def _oracle_lease(
    receipt: Report, deadline_utc: dt.datetime, service_seconds: int
) -> None:
    """Require the oracle lease to be held by a live unit and busy."""
    lock = receipt["managed_lock"]
    require(
        lock["pid"] > 0
        and lock["fd"] >= 0
        and lock["busy_exit"] == BUSY_EXIT
        and lock["unit_properties"]["ActiveState"] == "active"
        and lock["unit_properties"]["MainPID"] == str(lock["pid"]),
        "Managed oracle lease not proven busy",
    )
    live_service(lock, deadline_utc, service_seconds)
    expected_lock = Path(receipt["oracle_lock"])
    lock_fd = Path(f"/proc/{lock['pid']}/fd/{lock['fd']}")
    require(
        (lock_fd.stat().st_dev, lock_fd.stat().st_ino)
        == (expected_lock.stat().st_dev, expected_lock.stat().st_ino),
        "Managed lock FD inode changed",
    )
    busy = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
        ["flock", "--exclusive", "--nonblock", str(expected_lock), "true"],  # ruff: ignore[start-process-with-partial-path]  # flock from PATH
        check=False,
    ).returncode
    require(busy == BUSY_EXIT, "Canonical oracle mutex is not busy")


def runtime_gate(
    receipt: Report,
    env: Report,
    deadline_utc: dt.datetime,
    *,
    capture_window_profile: str | None = None,
) -> None:
    """Re-read the live runtime and require that it is the one receipted.

    The checks run in a fixed order: the window profile, the runner's identity
    and namespace, the capture gate, the namespace gate, the guest capture
    descriptor, the working image, the deadline, each managed recorder and
    last the oracle lease.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The runtime receipt.
    env : dict[str, typing.Any]
        The plan environment the receipt must agree with.
    deadline_utc : datetime.datetime
        The deadline of the epoch.
    capture_window_profile : str | None
        The capture window profile that the caller selected.
    """
    epoch_seconds, service_seconds = capture_window_bounds(
        receipt, env, capture_window_profile
    )
    _bound_to_plan(receipt, env)
    capture_gate(receipt)
    namespace_gate(receipt)
    require(
        os.readlink(f"/proc/{receipt['emulator_pid']}/fd/{GUEST_PCAP_FD}")  # ruff: ignore[os-readlink]  # /proc descriptor; the tests substitute os.readlink
        == receipt["guest_pcap"],
        "Guest PCAP FD changed",
    )
    image = Path(receipt["owned_working_image"])
    require(
        image.stat().st_ino == receipt["owned_working_image_inode"],
        "Working-image inode changed",
    )
    require(
        (deadline_utc - dt.datetime.now(dt.UTC)).total_seconds() > MIN_DEADLINE_SECONDS,
        "Epoch deadline too close",
    )
    require(
        (deadline_utc - utc(receipt["epoch_started_utc"])).total_seconds()
        <= epoch_seconds,
        "Epoch exceeds selected capture window",
    )
    for label in ("host", "namespace"):
        _recorder_unit(receipt, label, deadline_utc, service_seconds)
    _oracle_lease(receipt, deadline_utc, service_seconds)
