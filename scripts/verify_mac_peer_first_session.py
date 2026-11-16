#!/usr/bin/env python3
"""Verify the finite, interrupted Classic client capture across three views."""

import hashlib
import json
import typing as typ
from pathlib import Path

from pcap_tcp import read_packets
from script_cli import run
from verify_mac_peer_first_session_control import (
    check_control,
    check_control_session,
    check_data_session,
    field_map,
    parse_frames,
)
from verify_mac_peer_first_session_core import (
    AGREEMENT,
    CAPTURE_NAMES,
    CLIENT_CONTROL,
    CLIENT_DATA,
    CLIENT_DATA_TARGET,
    CLIENT_TARGET,
    CLIENT_TCP_CONNECTIONS,
    CONTROL_CONNECT_US,
    DATA_CONNECT_US,
    HOST_CLIENT,
    HOST_SERVER,
    HTTP_REQUEST,
    SERVER_CONTROL,
    SERVER_DATA,
    SERVER_DATA_NAT,
    SERVER_NAT,
    is_syn,
    require,
    selected_streams,
)
from verify_mac_peer_first_session_http import check_http, check_teardown

type Record = dict[str, typ.Any]
type Captures = tuple[list[Record], list[Record], list[Record]]

# The public names of the verifier, which its consumers import from this module.
__all__ = [
    "AGREEMENT",
    "CLIENT_CONTROL",
    "CLIENT_DATA",
    "CLIENT_DATA_TARGET",
    "CLIENT_TARGET",
    "CONTROL_CONNECT_US",
    "DATA_CONNECT_US",
    "HOST_CLIENT",
    "HOST_SERVER",
    "HTTP_REQUEST",
    "SERVER_CONTROL",
    "SERVER_DATA",
    "SERVER_DATA_NAT",
    "SERVER_NAT",
    "check_control",
    "check_http",
    "field_map",
    "main",
    "parse_frames",
    "require",
    "selected_streams",
    "verify",
]


def capture_packets(directory: Path) -> Captures:
    """Read the host, client and server captures in that order.

    Returns
    -------
    tuple[list[Record], list[Record], list[Record]]
        The host, client and server packets.
    """
    host = read_packets(directory / CAPTURE_NAMES[0])
    client = read_packets(directory / CAPTURE_NAMES[1])
    server = read_packets(directory / CAPTURE_NAMES[2])
    return host, client, server


def check_capture_files(directory: Path) -> None:
    """Require the captures to match the manifest's inventory, sizes and hashes."""
    manifest = json.loads((directory / "manifest.json").read_text())
    require(set(manifest["capture"]) == set(CAPTURE_NAMES), "Capture inventory differs")
    for name in CAPTURE_NAMES:
        path = directory / name
        require(
            path.stat().st_size == manifest["capture"][name]["size"]
            and hashlib.sha256(path.read_bytes()).hexdigest()
            == manifest["capture"][name]["sha256"],
            f"Capture SHA/size differs: {name}",
        )


def verify(directory: Path) -> dict[str, typ.Any]:
    """Verify the finite Classic client capture and summarise what it shows.

    Returns
    -------
    dict[str, typing.Any]
        The verified session's status, byte counts and checked records.
    """
    check_capture_files(directory)
    host, client, server = capture_packets(directory)
    require(
        len([p for p in client if is_syn(p)]) == CLIENT_TCP_CONNECTIONS,
        "Client guest TCP connection inventory differs",
    )
    control = check_control_session(host, client, server)
    data_out, data_in = check_data_session(client, server)
    http, last_request, client_fin = check_teardown(client, control.view)
    return {
        "status": "verified-partial-session",
        "control_bytes": {
            "client": len(control.outbound),
            "server": len(control.inbound),
        },
        "control": control.controls,
        "data_15501_bytes": {"client": len(data_out), "server": len(data_in)},
        "http_exchanges": http,
        "last_request_to_fin_us": client_fin - last_request,
        "control_syn_to_fin_us": client_fin - control.view[0]["timestamp_us"],
        "idle_test_valid": False,
    }


def show(directory: str) -> None:
    """Verify a finite Classic client capture and print its summary as JSON."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a finite Classic client capture directory."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
