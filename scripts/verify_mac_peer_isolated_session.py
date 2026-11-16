#!/usr/bin/env python3
"""Verify one isolated Classic client session from retained packet bytes."""

import datetime as dt
import hashlib
import json
import typing as typ
from pathlib import Path

from mothra_root import mothra_root
from pcap_tcp import read_packets
from script_cli import run
from verify_mac_peer_first_session import AGREEMENT, field_map, parse_frames, require
from verify_mac_peer_first_session_core import FIN_FLAG, is_syn
from verify_mac_peer_isolated_session_control import check_control, check_data
from verify_mac_peer_isolated_session_flow import flow, nat_session, syn
from verify_mac_peer_isolated_session_guest import (
    DNS_QUESTION,
    DNS_SUFFIX,
    check_dns_and_egress,
    check_observer,
    ipv4_records,
)
from verify_mac_peer_isolated_session_witness import check_isolation

if typ.TYPE_CHECKING:
    from verify_mac_peer_isolated_session_flow import NatSession

type Packet = dict[str, typ.Any]

CAPTURES = (
    "host-final.pcap",
    "client-guest-final.pcap",
    "server-guest-final.pcap",
    "nonlocal-known-ip.pcap",
)
GUEST_TCP_CONNECTIONS = 2
QUIET_WINDOW_US = 130_000_000  # the quiet window the session must keep open

# The public names of the verifier, which its tests and consumers import here.
__all__ = [
    "AGREEMENT",
    "CAPTURES",
    "DNS_QUESTION",
    "DNS_SUFFIX",
    "check_control",
    "check_data",
    "check_dns_and_egress",
    "check_isolation",
    "check_observer",
    "field_map",
    "flow",
    "ipv4_records",
    "main",
    "parse_frames",
    "require",
    "syn",
    "utc_us",
    "verify",
]


def utc_us(path: Path) -> int:
    """Read an action time, which must be UTC, as microseconds since the epoch.

    Returns
    -------
    int
        The time in microseconds.
    """
    value = path.read_text().strip().replace(" UTC", "+00:00")
    stamp = dt.datetime.fromisoformat(value)
    offset = stamp.utcoffset()
    require(
        offset is not None and offset.total_seconds() == 0,
        "Action time is not UTC",
    )
    return int(stamp.timestamp()) * 1_000_000 + stamp.microsecond


def check_manifest(directory: Path) -> None:
    """Require the captures and the helper source to match the manifest's hashes."""
    manifest = json.loads((directory / "manifest.json").read_text())
    require(set(manifest["capture"]) == set(CAPTURES), "Capture inventory differs")
    for name in CAPTURES:
        raw = (directory / name).read_bytes()
        item = manifest["capture"][name]
        require(
            len(raw) == item["size"]
            and hashlib.sha256(raw).hexdigest() == item["sha256"],
            f"Capture SHA/size differs: {name}",
        )
    require(
        hashlib.sha256(
            (mothra_root() / "scripts/mac_network_isolation.py").read_bytes()
        ).hexdigest()
        == manifest["helper_sha256"],
        "Isolated helper source differs",
    )


def check_client_tcp(client: list[Packet]) -> None:
    """Require the guest to open only the two expected TCP connections to the NAT."""
    require(
        len([
            p
            for p in client
            if p["src_ip"] == "10.0.2.15" and p["dst_ip"] != "10.0.2.2"
        ])
        == 0,
        "Public or unexpected guest TCP destination",
    )
    require(
        len([p for p in client if is_syn(p)]) == GUEST_TCP_CONNECTIONS,
        "Guest TCP connection count differs",
    )


def check_timing(
    directory: Path, control: NatSession, data: NatSession
) -> dict[str, typ.Any]:
    """Require the quiet window, the disconnect and the quit to fall in order.

    Returns
    -------
    dict[str, typing.Any]
        The DNS summary and the spans from the packets to the quiet end.
    """
    quiet_end = utc_us(directory / "quiet-end-time.txt")
    disconnect = utc_us(directory / "disconnect-time.txt")
    quit_time = utc_us(directory / "quit-time.txt")
    dns = check_dns_and_egress(directory / "client-guest-final.pcap", disconnect)
    last_data = max(p["timestamp_us"] for p in data.view)
    require(
        quiet_end - last_data >= QUIET_WINDOW_US
        and quiet_end - dns["last_predisconnect_error_us"] >= QUIET_WINDOW_US,
        "Finite quiet window shorter than 130 seconds",
    )
    require(
        quiet_end < disconnect < quit_time
        and any(
            p["flags"] & FIN_FLAG
            and p["src_port"] == control.syns[0]["src_port"]
            and p["timestamp_us"] > quiet_end
            for p in control.view
        ),
        "Disconnect/quit timing or FIN differs",
    )
    require(
        max(p["timestamp_us"] for p in control.view if p["payload_hex"]) < quiet_end,
        "Unexpected control payload in quiet window",
    )
    return {
        "dns": dns,
        "data_last_to_quiet_end_us": quiet_end - last_data,
        "dns_last_to_quiet_end_us": quiet_end - dns["last_predisconnect_error_us"],
    }


def verify(directory: Path) -> dict[str, typ.Any]:
    """Verify one isolated Classic client session directory and summarise it.

    Returns
    -------
    dict[str, typing.Any]
        The verified session's status, byte counts, DNS summary and port map.
    """
    check_manifest(directory)
    check_isolation(directory)
    check_observer(directory / "nonlocal-known-ip.pcap")
    host = read_packets(directory / CAPTURES[0])
    client = read_packets(directory / CAPTURES[1])
    server = read_packets(directory / CAPTURES[2])
    check_client_tcp(client)
    captures = (host, client, server)
    control = nat_session(captures, 15500, 5500)
    require(control.agrees, "Control bytes differ across NAT views")
    controls = check_control(control.outbound, control.inbound)
    data = nat_session(captures, 15501, 5501)
    require(data.agrees, "Data bytes differ across NAT views")
    check_data(
        bytes.fromhex(controls["data_reference_hex"]), data.outbound, data.inbound
    )
    timing = check_timing(directory, control, data)
    return {
        "status": "verified-isolated-finite-session",
        "control_bytes": {
            "client": len(control.outbound),
            "server": len(control.inbound),
        },
        "data_bytes": {"client": len(data.outbound), "server": len(data.inbound)},
        "control": controls,
        "dns": timing["dns"],
        "data_last_to_quiet_end_us": timing["data_last_to_quiet_end_us"],
        "dns_last_to_quiet_end_us": timing["dns_last_to_quiet_end_us"],
        "host_ports": {
            "control": control.syns[0]["src_port"],
            "data": data.syns[0]["src_port"],
        },
        "guest_ports": {
            "control": control.syns[1]["src_port"],
            "data": data.syns[1]["src_port"],
        },
        "server_nat_ports": {
            "control": control.syns[2]["src_port"],
            "data": data.syns[2]["src_port"],
        },
        "banner_ui_complete": False,
        "universal_500_schedule": False,
    }


def show(directory: str) -> None:
    """Verify an isolated Classic client session and print its summary as JSON."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify an isolated Classic client session directory."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
