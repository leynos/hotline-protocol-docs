"""Check the guest and host packet captures of the D1 console broadcast."""

import typing as typ
from pathlib import Path
from tempfile import TemporaryDirectory

from native_wire_names import FIELD_USER_ID, TYPE_USER_LEFT
from pcap_tcp import lifetime, read_packets, stream
from verify_mac_peer_first_session import field_map, parse_frames, require

type Report = dict[str, typ.Any]
type Packet = dict[str, typ.Any]
type Flow = tuple[bytes, bytes, bytes]

NAMES = ("ConsoleSender", "ConsoleRefuse", "ConsoleWaiting", "ConsoleUnauth")
GUEST_PORT = 5500  # the guest-side port that the D1 connections name
HOST_PORT = 15500  # the host-side port that the D1 connections name
GUEST_CONNECTIONS = 4  # the connections that the guest capture holds
HOST_COMPLETE_CONNECTIONS = 3  # the host connections with a complete SYN
D1_ACTIONS = 50  # the completed actions of the D1 console run
TAIL_USER_ID = b"\x00\x12"  # the user identifier of the teardown tail
PCAP_HEADER_BYTES = 24  # the global header of a capture file


def delta(path_before: Path, path_after: Path, temp: Path) -> Path:
    """Write the packets that the later guest capture appended to the earlier one.

    Parameters
    ----------
    path_before : pathlib.Path
        The earlier capture, which must be a prefix of the later one.
    path_after : pathlib.Path
        The later capture.
    temp : pathlib.Path
        The directory that receives the appended packets.

    Returns
    -------
    pathlib.Path
        The new capture file: the header of the later capture and the appended
        packets.
    """
    before, after = path_before.read_bytes(), path_after.read_bytes()
    require(
        after.startswith(before) and len(after) > len(before),
        "Guest PCAP append boundary differs",
    )
    result = temp / (path_after.stem + "-delta.pcap")
    result.write_bytes(before[:PCAP_HEADER_BYTES] + after[len(before) :])
    return result


def connection(report: Report, name: str) -> tuple[int, bytes, bytes]:
    """Return the local port and the sent and received bytes of one client.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified report of the capture.
    name : str
        The client connection name.

    Returns
    -------
    tuple[int, bytes, bytes]
        The local port, the bytes the client sent and the bytes it received.
    """
    events = [
        e
        for e in report["events"]
        if e["event"] == "connect" and e["connection"] == name
    ]
    require(len(events) == 1, f"Connection witness differs: {name}")
    port = events[0]["local_address"][1]
    streams = report["streams"][name]
    return (
        port,
        bytes.fromhex(streams["sent_hex"]),
        bytes.fromhex(streams["received_hex"]),
    )


def packets_for(
    packets: list[Packet], src: tuple[str, int], dst: tuple[str, int]
) -> tuple[list[Packet], bytes, bytes]:
    """Select the packets of the connection that opens with one SYN.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        The packets of a capture.
    src : tuple[str, int]
        The address and port of the sender of the SYN.
    dst : tuple[str, int]
        The address and port of the receiver of the SYN.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], bytes, bytes]
        The packets of the connection's lifetime, the bytes from ``src`` to ``dst``
        and the bytes from ``dst`` to ``src``.
    """
    syns = [
        p
        for p in packets
        if (p["src_ip"], p["src_port"]) == src
        and (p["dst_ip"], p["dst_port"]) == dst
        and p["flags"] & 2
        and not p["flags"] & 16
    ]
    require(len(syns) == 1, "SYN lifetime differs")
    selected = lifetime(packets, src, dst, syns[0]["timestamp_us"])
    return selected, stream(selected, src, dst), stream(selected, dst, src)


def partial(packets: list[Packet], src: tuple[str, int], dst: tuple[str, int]) -> bytes:
    """Reassemble a known missing-SYN direction from its first retained byte.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        The packets of a capture.
    src : tuple[str, int]
        The address and port of the sender of the direction.
    dst : tuple[str, int]
        The address and port of the receiver of the direction.

    Returns
    -------
    bytes
        The reassembled bytes of the direction.
    """
    chunks = [
        (p["sequence"], bytes.fromhex(p["payload_hex"]))
        for p in packets
        if (p["src_ip"], p["src_port"]) == src
        and (p["dst_ip"], p["dst_port"]) == dst
        and p["payload_hex"]
        and not p["flags"] & 4
    ]
    require(bool(chunks), "Empty partial host stream")
    start = min(seq for seq, _ in chunks)
    result = bytearray()
    for seq, data in sorted(chunks):
        offset = seq - start
        require(0 <= offset <= len(result), "Partial host TCP sequence gap")
        overlap = min(len(result) - offset, len(data))
        require(
            result[offset : offset + overlap] == data[:overlap],
            "Partial host overlap differs",
        )
        result.extend(data[overlap:])
    return bytes(result)


def check_tail(raw: bytes, expected_id: int) -> None:
    """Check that the bytes after a client's stream are one full 302 teardown frame.

    Parameters
    ----------
    raw : bytes
        The bytes that followed the client's retained stream.
    expected_id : int
        The transaction identifier of the teardown frame.
    """
    frames = parse_frames(raw)
    require(len(frames) == 1, "Teardown tail frame count differs")
    frame = frames[0]
    require(
        (frame["flags"], frame["is_reply"], frame["type"], frame["id"], frame["error"])
        == (0, 0, TYPE_USER_LEFT, expected_id, 0)
        and field_map(frame) == {FIELD_USER_ID: TAIL_USER_ID},
        "Teardown tail differs",
    )


def complete_syns(packets: list[Packet]) -> list[Packet]:
    """Return the packets that carry a SYN without an ACK.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        The packets of one capture.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets that open a connection.
    """
    return [p for p in packets if p["flags"] & 2 and not p["flags"] & 16]


def _guest_packets(root: Path) -> list[Packet]:
    """Read the guest capture of the D1 run, with its appended packets.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets of the guest capture after the first recording.
    """
    before = root / "guest-before.pcap"
    after = root / "guest-after.pcap"
    with TemporaryDirectory() as temporary:
        return read_packets(delta(before, after, Path(temporary)))


def _guest_flow(
    report: Report, name: str, tail_id: int | None, guest: list[Packet]
) -> tuple[int, Flow]:
    """Check one client's guest bytes against its report and its teardown tail.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified report of the capture.
    name : str
        The client connection name.
    tail_id : int | None
        The transaction identifier of the teardown tail, or ``None`` when the
        client never authenticated and no tail is expected.
    guest : list[dict[str, typing.Any]]
        The packets of the guest capture.

    Returns
    -------
    tuple[int, tuple[bytes, bytes, bytes]]
        The local port, and the bytes the client sent, the guest's outbound and the
        guest's inbound bytes of the connection.
    """
    port, sent, received = connection(report, name)
    _, go, gi = packets_for(guest, ("10.0.2.2", port), ("10.0.2.15", GUEST_PORT))
    require(
        go == sent and gi.startswith(received), f"Guest/report bytes differ: {name}"
    )
    tail = gi[len(received) :]
    if tail_id is None:
        require(not tail, "Unauthenticated teardown tail differs")
    else:
        check_tail(tail, tail_id)
    return port, (sent, go, gi)


def _check_sender_host(host: list[Packet], port: int, flow: Flow) -> None:
    """Check the host's reassembled bytes of the sending client.

    Parameters
    ----------
    host : list[dict[str, typing.Any]]
        The packets of the host capture.
    port : int
        The local port of the client.
    flow : tuple[bytes, bytes, bytes]
        The bytes the client sent, and the guest's outbound and inbound bytes.
    """
    sent, _, gi = flow
    host_src, host_dst = ("127.0.0.1", port), ("127.0.0.1", HOST_PORT)
    require(
        partial(host, host_src, host_dst) == sent[12:],  # the 12-byte handshake
        "Host sender suffix differs",
    )
    require(partial(host, host_dst, host_src) == gi, "Host sender inbound differs")


def _check_peer_host(host: list[Packet], name: str, port: int, flow: Flow) -> None:
    """Check that the host capture of one client matches the guest capture.

    Parameters
    ----------
    host : list[dict[str, typing.Any]]
        The packets of the host capture.
    name : str
        The client connection name.
    port : int
        The local port of the client.
    flow : tuple[bytes, bytes, bytes]
        The bytes the client sent, and the guest's outbound and inbound bytes.
    """
    host_src, host_dst = ("127.0.0.1", port), ("127.0.0.1", HOST_PORT)
    _, ho, hi = packets_for(host, host_src, host_dst)
    require((ho, hi) == flow[1:], f"Host/guest bytes differ: {name}")


def _check_host(host: list[Packet], name: str, port: int, flow: Flow) -> None:
    """Check the host capture of one client against the guest capture.

    Parameters
    ----------
    host : list[dict[str, typing.Any]]
        The packets of the host capture.
    name : str
        The client connection name.
    port : int
        The local port of the client.
    flow : tuple[bytes, bytes, bytes]
        The bytes the client sent, and the guest's outbound and inbound bytes.
    """
    if name == "ConsoleSender":
        _check_sender_host(host, port, flow)
    else:
        _check_peer_host(host, name, port, flow)


def check_capture(root: Path, report: Report) -> dict[str, typ.Any]:
    """Check the guest and host captures against the verified report.

    Parameters
    ----------
    root : pathlib.Path
        The corpus directory.
    report : dict[str, typing.Any]
        The verified report of the D1 capture.

    Returns
    -------
    dict[str, typing.Any]
        The connection counts and the retained scope of the captures.
    """
    guest = _guest_packets(root)
    host = read_packets(root / "host.pcap")
    require(
        len(complete_syns(guest)) == GUEST_CONNECTIONS,
        "Guest connection count differs",
    )
    require(
        len(complete_syns(host)) == HOST_COMPLETE_CONNECTIONS,
        "Host missing-SYN scope differs",
    )
    for name, tail_id in zip(NAMES, (6, 7, 5, None), strict=True):
        port, flow = _guest_flow(report, name, tail_id, guest)
        _check_host(host, name, port, flow)
    require(
        report["status"] == "completed" and report["completed_actions"] == D1_ACTIONS,
        "D1 action completion differs",
    )
    return {
        "guest_connections": 4,
        "host_complete_connections": 3,
        "host_sender_missing": "SYN and 12-byte handshake",
        "teardown_tails": "three full 302 frames retained",
    }
