#!/usr/bin/env python3
"""One-use isolated Classic Login107 ACK proxy with fixed local routes."""

import json
import socket
import subprocess  # ruff: ignore[suspicious-subprocess-import]  # reads the routing table with a fixed argv, no shell
import typing as typ
from pathlib import Path

from classic_login_proxy_constants import (
    BACKENDS,
    CLIENT_HELLO,
    DEADLINE_SECONDS,
    IP_BIN,
    LISTENERS,
    MAX_FRAME,
    MAX_OBSERVATION_NS,
    OBSERVATION_SECONDS,
    SERVER_HELLO,
    VARIANTS,
    Variant,
)
from classic_login_proxy_errors import fail
from classic_login_proxy_frames import parse_frame, transform_ack
from classic_login_proxy_relay import (
    accept_one,
    read_exact,
    read_frame,
    relay_data,
    relay_frames,
)
from classic_login_proxy_serve import ProxyRun
from classic_login_proxy_state import (
    Audit,
    ObservationCutoff,
    ObservationWatchdog,
    RosterState,
)
from script_cli import run

# The public names of the proxy, re-exported from its helper modules.
# Consumers: scripts/tests/test_classic_login_proxy.py, and the executed
# evidence files, which import CLIENT_HELLO, SERVER_HELLO and parse_frame.
__all__ = [
    "BACKENDS",
    "CLIENT_HELLO",
    "DEADLINE_SECONDS",
    "IP_BIN",
    "LISTENERS",
    "MAX_FRAME",
    "MAX_OBSERVATION_NS",
    "OBSERVATION_SECONDS",
    "SERVER_HELLO",
    "VARIANTS",
    "Audit",
    "ObservationCutoff",
    "ObservationWatchdog",
    "RosterState",
    "Variant",
    "accept_one",
    "main",
    "namespace_guard",
    "parse_frame",
    "read_exact",
    "read_frame",
    "relay_data",
    "relay_frames",
    "serve",
    "transform_ack",
]


def namespace_guard(expected_netns: int, host_netns: int) -> int:
    """Check that the proxy runs alone in a loopback-only network namespace.

    Parameters
    ----------
    expected_netns : int
        The inode of the namespace that the proxy must be running in.
    host_netns : int
        The inode of the host namespace, which the proxy must not share.

    Returns
    -------
    int
        The inode of the namespace that the proxy is running in.
    """
    if min(expected_netns, host_netns) <= 0 or expected_netns == host_netns:
        fail(ValueError, "Expected and host namespace inodes must be distinct")
    own = Path("/proc/self/ns/net").stat().st_ino
    if own != expected_netns or own == host_netns:
        fail(ValueError, "Proxy network namespace identity differs")
    if {name for _, name in socket.if_nameindex()} != {"lo"}:
        fail(ValueError, "Namespace has non-loopback interface")
    for family in ([], ["-6"]):
        result = subprocess.run(  # ruff: ignore[subprocess-without-shell-equals-true]  # fixed argv, no shell
            [IP_BIN, "-j", *family, "route", "show", "table", "main"],
            capture_output=True,
            text=True,
            check=True,
            timeout=2,
        )
        if json.loads(result.stdout) != []:
            fail(ValueError, "Namespace has nonlocal route")
    return own


def serve(
    variant: str, output: Path, expected_netns: int, host_netns: int
) -> dict[str, typ.Any]:
    """Run one proxy session and return its completed report.

    Parameters
    ----------
    variant : str
        One of the names in ``VARIANTS``.
    output : pathlib.Path
        The new directory that receives ``ready.json`` and ``report.json``.
    expected_netns : int
        The namespace inode that the proxy must be running in.
    host_netns : int
        The host namespace inode, which the proxy must not share.

    Returns
    -------
    dict[str, typing.Any]
        The report of the run, including its status.
    """
    if variant not in VARIANTS:
        fail(ValueError, "Unknown variant")
    netns = namespace_guard(expected_netns, host_netns)
    output.mkdir(parents=True, exist_ok=False)
    report: dict[str, typ.Any] = {
        "status": "failed",
        "variant": variant,
        "netns_inode": netns,
        "expected_netns_inode": expected_netns,
        "host_netns_inode": host_netns,
        "routes": BACKENDS,
        "listeners": LISTENERS,
        "deadline_seconds": DEADLINE_SECONDS,
    }
    return ProxyRun(variant, output, report).run()


def serve_command(
    *,
    variant: Variant,
    output: str,
    expected_netns_inode: int,
    host_netns_inode: int,
) -> None:
    """Run one proxy session from the command line, print its status and exit.

    Parameters
    ----------
    variant : Variant
        The variant that governs the controlled ACK.
    output : str
        The new directory that receives the ready and report files.
    expected_netns_inode : int
        The network namespace inode that the proxy must be running in.
    host_netns_inode : int
        The host network namespace inode, which the proxy must not share.

    Raises
    ------
    SystemExit
        With status 1 unless the run completed or was cut off on purpose.
    """
    result = serve(variant, Path(output), expected_netns_inode, host_netns_inode)
    print(result["status"])
    raise SystemExit(
        result["status"] not in {"completed", "intentional-observation-cutoff"}
    )


def main() -> None:
    """Parse the command line and run one proxy session."""
    run(serve_command, __doc__)


if __name__ == "__main__":
    main()
