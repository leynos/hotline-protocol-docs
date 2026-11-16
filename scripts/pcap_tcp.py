"""Read bounded Ethernet/IPv4 TCP observations without inventing missing bytes."""

from pcap_reader import Packet, read_packets

# read_packets lives in pcap_reader and stays importable from here, as every caller
# of this module uses it.
__all__ = ["direction", "lifetime", "read_packets", "stream"]

type Endpoint = tuple[str, int]

TCP_SYN = 2
TCP_RST = 4
TCP_ACK = 16
MAX_STREAM_BYTES = 8 * 1024 * 1024
SEQUENCE_MASK = 0xFFFFFFFF
LIFETIME_WINDOW_US = 2_000_000


def direction(
    packets: list[Packet], source: Endpoint, destination: Endpoint
) -> list[Packet]:
    """Select one TCP direction; port lifetimes must be scoped by the caller.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        Packets as returned by :func:`read_packets`.
    source : tuple[str, int]
        The sending address and port.
    destination : tuple[str, int]
        The receiving address and port.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets that go from ``source`` to ``destination``, in order.
    """
    return [
        p
        for p in packets
        if (p["src_ip"], p["src_port"]) == source
        and (p["dst_ip"], p["dst_port"]) == destination
    ]


def _segments(selected: list[Packet], base: int) -> list[tuple[int, bytes]]:
    """Collect the data segments of a direction as ``(offset, bytes)``.

    A reset may carry diagnostic bytes. They stay in the packet view but are not
    merged into the application stream (RFC 9293, section 3.5.3).

    Parameters
    ----------
    selected : list[dict[str, typing.Any]]
        The packets of one direction.
    base : int
        The sequence number of the first data byte.

    Returns
    -------
    list[tuple[int, bytes]]
        Offset from the base and data, in capture order.

    Raises
    ------
    ValueError
        If a segment ends beyond the analysis bound.
    """
    segments = []
    for packet in selected:
        if packet["flags"] & TCP_RST:
            continue
        data = bytes.fromhex(packet["payload_hex"])
        if data:
            offset = (
                packet["sequence"] + bool(packet["flags"] & TCP_SYN) - base
            ) & SEQUENCE_MASK
            if offset + len(data) > MAX_STREAM_BYTES:
                message = "TCP stream exceeds analysis bound"
                raise ValueError(message)
            segments.append((offset, data))
    return segments


def stream(packets: list[Packet], source: Endpoint, destination: Endpoint) -> bytes:
    """Reassemble a SYN-identified direction with matching overlaps and no gaps.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        Packets as returned by :func:`read_packets`.
    source : tuple[str, int]
        The sending address and port.
    destination : tuple[str, int]
        The receiving address and port.

    Returns
    -------
    bytes
        The application bytes of the direction.

    Raises
    ------
    ValueError
        If no SYN identifies the direction or SYNs differ, a segment passes the
        analysis bound, the bytes have a gap, or a retransmission conflicts.
    """
    selected = direction(packets, source, destination)
    syns = [p for p in selected if p["flags"] & TCP_SYN]
    if not syns or len({p["sequence"] for p in syns}) != 1:
        message = "Missing SYN or reused TCP port lifetime"
        raise ValueError(message)
    base = (syns[0]["sequence"] + 1) & SEQUENCE_MASK
    result = bytearray()
    for offset, data in sorted(_segments(selected, base)):
        if offset > len(result):
            message = "TCP sequence gap"
            raise ValueError(message)
        overlap = min(len(result) - offset, len(data))
        if result[offset : offset + overlap] != data[:overlap]:
            message = "Conflicting TCP retransmission"
            raise ValueError(message)
        result.extend(data[overlap:])
    return bytes(result)


def _first_syns(incoming: list[Packet]) -> dict[int, int]:
    """Map each SYN sequence number to the time its first SYN was seen.

    Returns
    -------
    dict[int, int]
        Sequence number to timestamp in microseconds. A SYN that carries an
        acknowledgement is not a first SYN.
    """
    first_syns: dict[int, int] = {}
    for packet in incoming:
        if packet["flags"] & TCP_SYN and not packet["flags"] & TCP_ACK:
            first_syns.setdefault(packet["sequence"], packet["timestamp_us"])
    return first_syns


def lifetime(
    packets: list[Packet],
    source: Endpoint,
    destination: Endpoint,
    connect_us: int,
) -> list[Packet]:
    """Select a unique SYN lifetime near a socket event; reject ambiguous reuse.

    Parameters
    ----------
    packets : list[dict[str, typing.Any]]
        Packets as returned by :func:`read_packets`.
    source : tuple[str, int]
        The connecting address and port.
    destination : tuple[str, int]
        The listening address and port.
    connect_us : int
        The socket event's time in microseconds.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets of both directions from the lifetime's first SYN, inclusive,
        to the next SYN of another sequence number, exclusive.

    Raises
    ------
    ValueError
        If no SYN, or more than one, lies within two seconds of the event.
    """
    first_syns = _first_syns(direction(packets, source, destination))
    candidates = [
        (sequence, when)
        for sequence, when in first_syns.items()
        if abs(when - connect_us) <= LIFETIME_WINDOW_US
    ]
    if len(candidates) != 1:
        message = "Missing or ambiguous SYN lifetime near socket event"
        raise ValueError(message)
    sequence, start = candidates[0]
    end = min(
        (
            when
            for other, when in first_syns.items()
            if other != sequence and when > start
        ),
        default=float("inf"),
    )
    flows = ((source, destination), (destination, source))
    return [
        p
        for p in packets
        if start <= p["timestamp_us"] < end
        and ((p["src_ip"], p["src_port"]), (p["dst_ip"], p["dst_port"])) in flows
    ]
