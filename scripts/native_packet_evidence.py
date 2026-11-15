"""Reconcile socket recordings with independently observed TCP lifetimes."""

import dataclasses as dc
import datetime as dt
import typing as typ

from pcap_tcp import direction, lifetime, stream
from verify_native_core import require

type Packet = dict[str, typ.Any]
type Address = tuple[str, int]

TCP_FIN = 1
TCP_RST = 4
TCP_CLOSE_FLAGS = TCP_FIN | TCP_RST
MICROSECONDS_PER_SECOND = 1_000_000
NANOSECONDS_PER_MICROSECOND = 1000
# native-capture-workflow.md: host ports 15500-15503 forward to guest ports
# 5500-5503. The guest sees its relay client as 10.0.2.2 and itself as 10.0.2.15.
GUEST_CLIENT_HOST = "10.0.2.2"
GUEST_SERVER_HOST = "10.0.2.15"
HOST_FORWARD_BASE = 15500
GUEST_SERVER_BASE = 5500


@dc.dataclass(frozen=True, slots=True)
class Recording:
    """The observations that a socket report is reconciled with.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The retained capture report.
    host : list[dict[str, typing.Any]]
        Packets seen on the host.
    guest : list[dict[str, typing.Any]]
        Packets seen inside the guest.
    unread_output : dict[str, bytes] | None
        Server bytes the client never read, by connection, on the host.
    guest_unread_output : dict[str, bytes] | None
        The same for the guest view, when it differs from the host's.
    """

    report: dict[str, typ.Any]
    host: list[Packet]
    guest: list[Packet]
    unread_output: dict[str, bytes] | None = None
    guest_unread_output: dict[str, bytes] | None = None

    def unread(self, name: str, label: str) -> bytes:
        """Return the unread server bytes of one connection in one view.

        Returns
        -------
        bytes
            The guest view's bytes when it has its own, else the host's.
        """
        own = label == "guest" and self.guest_unread_output is not None
        view = self.guest_unread_output if own else self.unread_output
        return (view or {}).get(name, b"")


def _addresses(event: dict[str, typ.Any]) -> tuple[Address, Address, Address, Address]:
    """Name a connection's four endpoints, as the host and the guest see them.

    Returns
    -------
    tuple[Address, Address, Address, Address]
        The host client, the host server, the guest client and the guest server.
    """
    source = typ.cast("Address", tuple(event["local_address"]))
    endpoint = typ.cast("Address", tuple(event["peer_address"]))
    guest_source = (GUEST_CLIENT_HOST, source[1])
    guest_endpoint = (
        GUEST_SERVER_HOST,
        GUEST_SERVER_BASE + endpoint[1] - HOST_FORWARD_BASE,
    )
    return source, endpoint, guest_source, guest_endpoint


def _check_views(
    recording: Recording, name: str, event: dict[str, typ.Any], connect_us: int
) -> list[Packet]:
    """Check both views' streams against the recorded bytes.

    Returns
    -------
    list[dict[str, typing.Any]]
        The guest view's packets of this connection's lifetime.
    """
    source, endpoint, guest_source, guest_endpoint = _addresses(event)
    recorded = recording.report["streams"][name]
    packets: list[Packet] = []
    for label, all_packets, client, server in [
        ("host", recording.host, source, endpoint),
        ("guest", recording.guest, guest_source, guest_endpoint),
    ]:
        packets = lifetime(all_packets, client, server, connect_us)
        require(
            stream(packets, client, server).hex() == recorded["sent_hex"],
            f"{name}: {label} input differs",
        )
        require(
            stream(packets, server, client)
            == bytes.fromhex(recorded["received_hex"]) + recording.unread(name, label),
            f"{name}: {label} output differs",
        )
    return packets


def _guest_close(
    packets: list[Packet], guest_source: Address, guest_endpoint: Address
) -> tuple[bool, str | None]:
    """Say whether the guest server closed first, and how.

    Returns
    -------
    tuple[bool, str | None]
        Whether the server's first close preceded the client's, and its kind
        (``RST`` or ``FIN``), or ``None`` when the server never closed.
    """
    incoming = direction(packets, guest_source, guest_endpoint)
    outgoing = direction(packets, guest_endpoint, guest_source)
    client_ends = [p for p in incoming if p["flags"] & TCP_CLOSE_FLAGS]
    server_ends = [p for p in outgoing if p["flags"] & TCP_CLOSE_FLAGS]
    server_first = bool(server_ends) and (
        not client_ends
        or server_ends[0]["timestamp_us"] < client_ends[0]["timestamp_us"]
    )
    if not server_ends:
        return server_first, None
    return server_first, "RST" if server_ends[0]["flags"] & TCP_RST else "FIN"


def _facts(recording: Recording, name: str, port: int) -> dict[str, typ.Any]:
    """Summarise the recorded byte counts and the host's unread tail.

    Returns
    -------
    dict[str, typing.Any]
        The client port, the byte counts and the unread tail in hexadecimal.
    """
    recorded = recording.report["streams"][name]
    return {
        "client_port": port,
        "sent_bytes": len(bytes.fromhex(recorded["sent_hex"])),
        "received_bytes": len(bytes.fromhex(recorded["received_hex"])),
        "unread_output_hex": (recording.unread_output or {}).get(name, b"").hex(),
    }


def _observe(
    recording: Recording, event: dict[str, typ.Any], started_us: float
) -> dict[str, typ.Any]:
    """Reconcile one connection's recording with both packet views.

    Returns
    -------
    dict[str, typing.Any]
        The independently observed facts about this connection.
    """
    name = event["connection"]
    connect_us = int(started_us + event["elapsed_ns"] / NANOSECONDS_PER_MICROSECOND)
    packets = _check_views(recording, name, event, connect_us)
    source, _, guest_source, guest_endpoint = _addresses(event)
    server_first, kind = _guest_close(packets, guest_source, guest_endpoint)
    observed = _facts(recording, name, source[1])
    observed["guest_server_initiated_close"] = server_first
    observed["guest_server_close_kind"] = kind
    if recording.guest_unread_output is not None:
        observed["guest_unread_output_hex"] = recording.guest_unread_output.get(
            name, b""
        ).hex()
    return observed


class GuestView(typ.TypedDict, total=False):
    """The optional guest-side observation of the unread server bytes."""

    guest_unread_output: dict[str, bytes] | None


def reconcile(
    report: dict[str, typ.Any],
    host: list[Packet],
    guest: list[Packet],
    unread_output: dict[str, bytes] | None = None,
    **guest_view: typ.Unpack[GuestView],
) -> dict[str, dict[str, typ.Any]]:
    """Check both prefixes and retained tails, including post-close divergence.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The observed facts of each connection, by name.
    """
    recording = Recording(
        report, host, guest, unread_output, guest_view.get("guest_unread_output")
    )
    started_us = (
        dt.datetime.fromisoformat(report["started_at_utc"]).timestamp()
        * MICROSECONDS_PER_SECOND
    )
    observations = {
        event["connection"]: _observe(recording, event, started_us)
        for event in report["events"]
        if event["event"] == "connect"
    }
    require(set(observations) == set(report["streams"]), "Missing socket identity")
    return observations
