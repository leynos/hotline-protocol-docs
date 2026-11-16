#!/usr/bin/env python3
"""Verify bounded native handshake outcomes against TCP and Ethernet records."""

import dataclasses as dc
import json
import typing as typ
from pathlib import Path

from native_packet_evidence import (
    GUEST_CLIENT_HOST,
    GUEST_SERVER_BASE,
    GUEST_SERVER_HOST,
    HOST_FORWARD_BASE,
    TCP_CLOSE_FLAGS,
    TCP_FIN,
    TCP_RST,
)
from native_wire_names import HANDSHAKE_REPLY_HEX, HANDSHAKE_REQUEST_HEX
from pcap_tcp import direction, read_packets, stream
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_handshake_timing import verify_timing

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

# The timing checks live in verify_native_handshake_timing; verify_timing stays
# importable from this module. verify is imported by test_native_handshakes;
# HANDSHAKE, SUCCESS and FAILURE are kept because the original module defined
# them publicly.
__all__ = [
    "FAILURE",
    "HANDSHAKE",
    "SUCCESS",
    "main",
    "verify",
    "verify_timing",
]

HANDSHAKE = bytes.fromhex(HANDSHAKE_REQUEST_HEX)
SUCCESS = bytes.fromhex(HANDSHAKE_REPLY_HEX)
FAILURE = bytes.fromhex("5452545000000001")  # `TRTP` and a non-zero result
FAILING_HANDSHAKES = {"wrong-version", "wrong-subprotocol", "wrong-subversion"}
SEGMENTED_SPLITS = [1, 4, 8, 10, 11]
EXPECTED_NAMES = {
    "normal-control",
    "normal-alternate-control",
    "wrong-magic",
    "wrong-version",
    "wrong-subprotocol",
    "wrong-subversion",
    "short-eof",
    "pipelined-login",
    "thirteenth-byte-is-frame-prefix",
} | {f"segmented-{n}" for n in SEGMENTED_SPLITS}
TRUNCATED_BYTES = 11  # the handshake less its last byte
HANDSHAKE_BYTES = 12
QUIET_SECONDS = 3
NANOSECONDS_PER_SECOND = 1e9
LOGIN_FRAMES = [(1, 0, 0), (0, 354, 0), (0, 109, 0)]  # is_reply, type, error
SCOPE = (
    "Recorded boundary exchanges and guest FIN/RST ordering only; no timer or "
    "alternate-wrapper negotiation completion"
)


@dc.dataclass(frozen=True, slots=True)
class Exchange:
    """One recorded handshake case, with its guest-side close observations."""

    name: str
    path: Path
    report: Report
    request: bytes
    response: bytes
    outgoing: Packets
    server_end: Packets
    client_end: Packets

    @property
    def server_first(self) -> bool:
        """Whether the guest closed before the client did."""
        return (
            not self.client_end
            or self.server_end[0]["timestamp_us"] < self.client_end[0]["timestamp_us"]
        )


def check_failure(exchange: Exchange) -> None:
    """Check a refused handshake: the failure word, the close and its order."""
    name = exchange.name
    require(exchange.response == FAILURE, name + ": failure handshake changed")
    require(exchange.server_first, name + ": server did not initiate close")
    last_data = max(
        p["timestamp_us"]
        for p in exchange.outgoing
        if p["payload_hex"] and not p["flags"] & TCP_RST
    )
    require(
        last_data <= exchange.server_end[0]["timestamp_us"],
        name + ": close preceded failure bytes",
    )


def check_wrong_magic(exchange: Exchange) -> None:
    """Check that a wrong magic is reset with no application bytes."""
    require(
        not exchange.response
        and exchange.server_first
        and exchange.server_end[0]["flags"] & TCP_RST,
        "Wrong magic did not reset without application bytes",
    )


def check_short_eof(exchange: Exchange) -> None:
    """Check that a truncated handshake was half-closed by the client first."""
    require(
        exchange.request == HANDSHAKE[:TRUNCATED_BYTES] and not exchange.response,
        "Truncated handshake changed",
    )
    require(
        bool(exchange.client_end)
        and not exchange.server_first
        and exchange.client_end[0]["flags"] & TCP_FIN,
        "Truncated input did not half-close first",
    )


def check_alternate(exchange: Exchange) -> None:
    """Check that the alternate-port observation was closed by the client."""
    require(
        exchange.request == HANDSHAKE and not exchange.response,
        "Alternate-port observation changed",
    )
    require(
        bool(exchange.client_end) and not exchange.server_first,
        "Alternate-port close was not client initiated",
    )


def check_segmented(exchange: Exchange) -> None:
    """Check a handshake that was sent in two pieces with a quiet between them."""
    name, report = exchange.name, exchange.report
    split = int(name.split("-")[1])
    require(exchange.request == HANDSHAKE, name + ": segmented input changed")
    sends = [e for e in report["events"] if e["event"] == "send"]
    require(
        bytes.fromhex(sends[0]["hex"]) == HANDSHAKE[:split],
        name + ": split point changed",
    )
    require(
        any(e["event"] == "quiet" for e in report["events"]),
        name + ": no bounded quiet observation",
    )
    plan = json.loads((exchange.path.parent / "plan.json").read_text())
    window = next(s["timeout"] for s in plan["steps"] if s["op"] == "expect_quiet")
    require(window >= QUIET_SECONDS, name + ": quiet observation too short")
    quiet = next(e for e in report["events"] if e["event"] == "quiet")
    require(
        quiet["action"] < sends[1]["action"]
        and quiet["elapsed_ns"] - sends[0]["elapsed_ns"]
        >= window * NANOSECONDS_PER_SECOND,
        name + ": quiet timing/order evidence changed",
    )


def check_success(exchange: Exchange) -> None:
    """Check a handshake that the server accepted, and the login that followed."""
    name = exchange.name
    require(exchange.response.startswith(SUCCESS), name + ": success handshake changed")
    if name == "normal-control":
        require(
            exchange.request == HANDSHAKE and exchange.response == SUCCESS,
            "Normal handshake bytes changed",
        )
    if name.startswith("segmented-"):
        check_segmented(exchange)
    if name in {"pipelined-login", "thirteenth-byte-is-frame-prefix"}:
        require(
            exchange.request[:HANDSHAKE_BYTES] == HANDSHAKE,
            name + ": handshake prefix changed",
        )
        require(
            [(f["is_reply"], f["type"], f["error"]) for f in exchange.report["frames"]]
            == LOGIN_FRAMES,
            name + ": pipelined login failed",
        )


def check_outcome(exchange: Exchange) -> None:
    """Check the case-specific outcome of one handshake."""
    name = exchange.name
    if name in FAILING_HANDSHAKES:
        check_failure(exchange)
    elif name == "wrong-magic":
        check_wrong_magic(exchange)
    elif name == "short-eof":
        check_short_eof(exchange)
    elif name == "normal-alternate-control":
        check_alternate(exchange)
    else:
        check_success(exchange)


def check_streams(
    name: str, report: Report, host: Packets, guest: Packets
) -> tuple[bytes, bytes, tuple[str, int], tuple[str, int]]:
    """Check that the socket's bytes are the bytes in the host and guest packets.

    Returns
    -------
    tuple[bytes, bytes, tuple[str, int], tuple[str, int]]
        The bytes sent, the bytes received, and the client and server addresses
        as the guest saw them.
    """
    connect = report["events"][0]
    source = tuple(connect["local_address"])
    endpoint = tuple(connect["peer_address"])
    request = bytes.fromhex(report["streams"]["main"]["sent_hex"])
    response = bytes.fromhex(report["streams"]["main"]["received_hex"])
    require(
        stream(host, source, endpoint) == request, name + ": host sent bytes differ"
    )
    require(
        stream(host, endpoint, source) == response,
        name + ": host received bytes differ",
    )
    guest_client = (GUEST_CLIENT_HOST, source[1])
    guest_server = (
        GUEST_SERVER_HOST,
        GUEST_SERVER_BASE + endpoint[1] - HOST_FORWARD_BASE,
    )
    require(
        stream(guest, guest_client, guest_server) == request,
        name + ": guest input differs",
    )
    require(
        stream(guest, guest_server, guest_client) == response,
        name + ": guest output differs",
    )
    return request, response, guest_client, guest_server


def closes(
    guest: Packets, client: tuple[str, int], server: tuple[str, int]
) -> tuple[Packets, Packets, Packets]:
    """Find the guest's view of how each side of the connection ended.

    Returns
    -------
    tuple[list, list, list]
        The server's packets, its FIN and RST packets, and the client's.
    """
    incoming = direction(guest, client, server)
    outgoing = direction(guest, server, client)
    server_end = [p for p in outgoing if p["flags"] & TCP_CLOSE_FLAGS]
    client_end = [p for p in incoming if p["flags"] & TCP_CLOSE_FLAGS]
    return outgoing, server_end, client_end


def open_exchange(path: Path, host: Packets, guest: Packets) -> tuple[Exchange, int]:
    """Check one recorded case's streams and gather its close observations.

    Returns
    -------
    tuple[Exchange, int]
        The exchange, and the guest server's port.
    """
    name = path.parent.name
    report = verify_capture(path.parent)
    wanted = "failed" if name == "normal-alternate-control" else "completed"
    require(report["status"] == wanted, name + ": capture status changed")
    request, response, client, server = check_streams(name, report, host, guest)
    outgoing, server_end, client_end = closes(guest, client, server)
    require(bool(server_end), name + ": incomplete guest close observation")
    return (
        Exchange(
            name, path, report, request, response, outgoing, server_end, client_end
        ),
        server[1],
    )


def check_case(path: Path, host: Packets, guest: Packets) -> Report:
    """Check one recorded case and summarise its close observations.

    Returns
    -------
    dict[str, typing.Any]
        The case, its ports, its byte counts and which side closed first.
    """
    exchange, server_port = open_exchange(path, host, guest)
    check_outcome(exchange)
    server_end = exchange.server_end
    return {
        "case": exchange.name,
        "host_client_port": exchange.report["events"][0]["local_address"][1],
        "guest_server_port": server_port,
        "sent_bytes": len(exchange.request),
        "received_bytes": len(exchange.response),
        "guest_first_close": "server" if exchange.server_first else "client",
        "guest_server_close_kind": "RST" if server_end[0]["flags"] & TCP_RST else "FIN",
        "reset_diagnostics_hex": [
            p["payload_hex"]
            for p in exchange.outgoing
            if p["flags"] & TCP_RST and p["payload_hex"]
        ],
        "capture_status": exchange.report["status"],
    }


def verify(directory: Path) -> Report:
    """Match each addressed socket to exact guest TCP bytes and close ordering.

    Returns
    -------
    dict[str, typing.Any]
        The observation of every case, the timing checks and the scope.
    """
    guest = read_packets(directory / "guest.pcap")
    host = read_packets(directory / "host.pcap")
    observations = [
        check_case(path, host, guest)
        for path in sorted((directory / "transcripts").glob("*/report.json"))
    ]
    require(
        {o["case"] for o in observations} == EXPECTED_NAMES,
        "Incomplete handshake case catalogue",
    )
    return {
        "cases": observations,
        "timing": verify_timing(directory, guest),
        "scope": SCOPE,
    }


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify one immutable handshake evidence batch."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
