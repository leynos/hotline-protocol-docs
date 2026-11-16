"""Find each guest connection's SYN and follow its bytes through the NAT views."""

import dataclasses as dc
import typing as typ

from pcap_tcp import lifetime, stream
from verify_mac_peer_first_session import require
from verify_mac_peer_first_session_core import is_syn

type Packet = dict[str, typ.Any]
type Captures = tuple[list[Packet], list[Packet], list[Packet]]

NEAR_WINDOW_US = 2_000_000  # how close a SYN must be to the time it is matched to


def syn(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    packets: list[Packet],
    src: str,
    dst: str,
    port: int,
    near: int | None = None,
    source_port: int | None = None,
) -> Packet:
    """Return the one SYN from src to dst on port, optionally near a time and port.

    Returns
    -------
    dict[str, typing.Any]
        The matching SYN packet.
    """
    candidates = [
        p
        for p in packets
        if p["src_ip"] == src
        if p["dst_ip"] == dst
        if p["dst_port"] == port
        if is_syn(p)
        if near is None or abs(p["timestamp_us"] - near) < NEAR_WINDOW_US
        if source_port is None or p["src_port"] == source_port
    ]
    require(len(candidates) == 1, "Missing or ambiguous session SYN")
    return candidates[0]


def flow(packets: list[Packet], item: Packet) -> tuple[list[Packet], bytes, bytes]:
    """Return a connection's lifetime packets and the bytes each side sent.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], bytes, bytes]
        The lifetime packets, the initiator's bytes and the responder's bytes.
    """
    source = (item["src_ip"], item["src_port"])
    target = (item["dst_ip"], item["dst_port"])
    view = lifetime(packets, source, target, item["timestamp_us"])
    return view, stream(view, source, target), stream(view, target, source)


@dc.dataclass(frozen=True, slots=True)
class NatSession:
    """One guest connection as the host, client and server NAT views record it."""

    view: list[Packet]
    outbound: bytes
    inbound: bytes
    agrees: bool
    syns: tuple[Packet, Packet, Packet]


def connection_syns(
    captures: Captures, port: int, server_port: int
) -> tuple[Packet, Packet, Packet]:
    """Find the connection's SYN in the host, client and server captures, in order.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any], dict[str, typing.Any]]
        The host, client and server SYNs.
    """
    host_syn = syn(captures[0], "127.0.0.1", "127.0.0.1", port)
    guest_syn = syn(
        captures[1], "10.0.2.15", "10.0.2.2", port, host_syn["timestamp_us"]
    )
    server_syn = syn(
        captures[2],
        "10.0.2.2",
        "10.0.2.15",
        server_port,
        host_syn["timestamp_us"],
        host_syn["src_port"],
    )
    return host_syn, guest_syn, server_syn


def nat_session(captures: Captures, port: int, server_port: int) -> NatSession:
    """Follow one guest connection through the three views and compare its bytes.

    Returns
    -------
    NatSession
        The host view, the host-side bytes, whether all views agree, and the SYNs.
    """
    syns = connection_syns(captures, port, server_port)
    flows = list(map(flow, captures, syns, strict=True))
    view, outbound, inbound = flows[0]
    agrees = (
        len({out for _, out, _ in flows}) == 1
        and len({inbound_bytes for _, _, inbound_bytes in flows}) == 1
    )
    return NatSession(view, outbound, inbound, agrees, syns)
