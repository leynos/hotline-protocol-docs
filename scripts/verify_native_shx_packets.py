"""Pair the peer's traced socket bytes with the host and guest packet captures."""

import json
import re
import typing as typ

from pcap_tcp import lifetime, stream
from shx_syscalls import socket_io
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

# mac-peer-first-session.md: the peer reaches the control port, 15500, and the
# transfer port, 15501, on the host. The guest sees each ten thousand lower.
CONTROL_PORT = 15500
GUEST_PORT_SHIFT = 10000
HOST_ADDRESS = "127.0.0.1"
GUEST_CLIENT_ADDRESS = "10.0.2.2"
GUEST_SERVER_ADDRESS = "10.0.2.15"


def has_exec(trace: str, pid: int, report: Report) -> bool:
    """Tell whether a process of the trace started the peer binary successfully.

    Returns
    -------
    bool
        Whether the trace has a successful ``execve`` of the peer by ``pid``.
    """
    encoded = "".join(f"\\x{b:02x}" for b in report["command"][-3].encode())
    pattern = rf'^{pid} \d+\.\d+ execve\("{re.escape(encoded)}", .* = 0$'
    return re.search(pattern, trace, re.MULTILINE) is not None


def check_connection(
    selected: list[Report], host: list[Report], guest: list[Report]
) -> Report:
    """Check that one traced connection matches both packet captures.

    Returns
    -------
    dict[str, typing.Any]
        The port, endpoint and process of the connection, and its bytes.
    """
    port = selected[0]["client_port"]
    endpoint = selected[0]["server_port"]
    require(
        len({(r["pid"], r["fd"], r["server_port"]) for r in selected}) == 1,
        "Ambiguous peer socket identity",
    )
    sent = b"".join(r["bytes"] for r in selected if r["operation"] == "write")
    received = b"".join(r["bytes"] for r in selected if r["operation"] == "read")
    for label, packets, client, server in [
        (
            "host",
            host,
            (HOST_ADDRESS, port),
            (HOST_ADDRESS, endpoint),
        ),
        (
            "guest",
            guest,
            (GUEST_CLIENT_ADDRESS, port),
            (GUEST_SERVER_ADDRESS, endpoint - GUEST_PORT_SHIFT),
        ),
    ]:
        observed = lifetime(packets, client, server, selected[0]["timestamp_us"])
        require(stream(observed, client, server) == sent, label + " peer input differs")
        require(
            stream(observed, server, client) == received,
            label + " peer output differs",
        )
    return {
        "port": port,
        "endpoint": endpoint,
        "pid": selected[0]["pid"],
        "sent": sent,
        "received": received,
    }


def check_packets(case: Path, host: list[Report], guest: list[Report]) -> list[Report]:
    """Pair every traced connection of a case with the packet captures.

    Returns
    -------
    list[dict[str, typing.Any]]
        The connections, ordered by client port.
    """
    trace = (case / "syscalls.log").read_text()
    records = socket_io(trace)
    require(bool(records), "Missing peer socket I/O")
    connections = [
        check_connection([r for r in records if r["client_port"] == port], host, guest)
        for port in sorted({r["client_port"] for r in records})
    ]
    control = [c for c in connections if c["endpoint"] == CONTROL_PORT]
    require(len(control) == 1, "Expected exactly one peer control connection")
    report = json.loads((case / "report.json").read_text())
    require(
        has_exec(trace, control[0]["pid"], report),
        "Control socket process lacks successful peer exec",
    )
    return connections
