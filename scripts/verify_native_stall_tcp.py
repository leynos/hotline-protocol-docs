"""Read the TCP window and window scale of every record of a packet capture.

The stall verifier needs the advertised window of each acknowledgement, which
``pcap_tcp`` does not expose, so this module reads the records directly.
"""

import struct
import typing as typ

from verify_native_core import require

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

type Json = dict[str, typ.Any]

MICROSECONDS_PER_SECOND = 1_000_000
# Fields of a classic packet capture file and of the frames it holds.
PCAP_HEADER_BYTES = 24
PCAP_RECORD_BYTES = 16
PCAP_LITTLE_ENDIAN = b"\xd4\xc3\xb2\xa1"
PCAP_BIG_ENDIAN = b"\xa1\xb2\xc3\xd4"
ETHERNET_BYTES = 14
ETHERTYPE_START = 12
ETHERTYPE_IPV4 = b"\x08\x00"
IP_PROTOCOL = 9
IP_TCP = 6
IP_LENGTH_START = 2
IP_LENGTH_END = 4
IP_HEADER_WORDS_MASK = 15
TCP_OFFSET_BYTE = 12
TCP_WINDOW_START = 14
TCP_WINDOW_END = 16
TCP_FIXED_BYTES = 20
TCP_OPTION_END = 0
TCP_OPTION_NOP = 1
TCP_OPTION_WINDOW_SCALE = 3
TCP_OPTION_MIN_BYTES = 2  # the kind and the length
TCP_WINDOW_SCALE_BYTES = 3
TCP_MAX_WINDOW_SHIFT = 14


def window_scales(options: bytes) -> list[int]:
    """Collect the window-scale shifts among a segment's TCP options.

    Returns
    -------
    list[int]
        The shift of each window-scale option, in order.
    """
    scales: list[int] = []
    pos = 0
    while pos < len(options):
        kind = options[pos]
        if kind == TCP_OPTION_END:
            break
        if kind == TCP_OPTION_NOP:
            pos += 1
            continue
        require(pos + TCP_OPTION_MIN_BYTES <= len(options), "Truncated TCP option")
        length = options[pos + 1]
        require(
            TCP_OPTION_MIN_BYTES <= length <= len(options) - pos, "Invalid TCP option"
        )
        if kind == TCP_OPTION_WINDOW_SCALE:
            require(
                length == TCP_WINDOW_SCALE_BYTES
                and options[pos + 2] <= TCP_MAX_WINDOW_SHIFT,
                "Invalid window scale",
            )
            scales.append(options[pos + 2])
        pos += length
    return scales


def tcp_header(frame: bytes, time_us: int) -> Json | None:
    """Read the window and window scale out of an Ethernet frame.

    Returns
    -------
    dict[str, typing.Any] | None
        The advertised window, the scale and the time, or ``None`` for a frame
        that is not TCP over IPv4.
    """
    if frame[ETHERTYPE_START : ETHERTYPE_START + 2] != ETHERTYPE_IPV4:
        return None
    ip = frame[ETHERNET_BYTES:]
    if ip[IP_PROTOCOL] != IP_TCP:
        return None
    tcp = ip[
        (ip[0] & IP_HEADER_WORDS_MASK) * 4 : int.from_bytes(
            ip[IP_LENGTH_START:IP_LENGTH_END], "big"
        )
    ]
    offset = (tcp[TCP_OFFSET_BYTE] >> 4) * 4
    require(TCP_FIXED_BYTES <= offset <= len(tcp), "Invalid TCP offset")
    scales = window_scales(tcp[TCP_FIXED_BYTES:offset])
    require(len(scales) <= 1, "Ambiguous window scale")
    return {
        "window": int.from_bytes(tcp[TCP_WINDOW_START:TCP_WINDOW_END], "big"),
        "scale": scales[0] if scales else None,
        "time_us": time_us,
    }


def pcap_records(path: Path) -> cabc.Iterator[tuple[int, bytes]]:
    """Read the records of a classic capture file.

    Yields
    ------
    tuple[int, bytes]
        The time of each record in microseconds, and its frame.

    Raises
    ------
    ValueError
        If the file is not a classic capture.
    """
    with path.open("rb") as source:
        header = source.read(PCAP_HEADER_BYTES)
        order = {PCAP_LITTLE_ENDIAN: "<", PCAP_BIG_ENDIAN: ">"}.get(header[:4])
        if order is None:
            message = "PCAP magic differs"
            raise ValueError(message)
        while record := source.read(PCAP_RECORD_BYTES):
            require(len(record) == PCAP_RECORD_BYTES, "Truncated PCAP record")
            seconds, micros, size, original = struct.unpack(order + "IIII", record)
            require(
                size == original and micros < MICROSECONDS_PER_SECOND,
                "Invalid PCAP record",
            )
            frame = source.read(size)
            require(len(frame) == size, "Truncated PCAP bytes")
            yield seconds * MICROSECONDS_PER_SECOND + micros, frame


def raw_headers(path: Path) -> dict[int, Json]:
    """Return TCP windows/options indexed by the original PCAP record number.

    Returns
    -------
    dict[int, dict[str, typing.Any]]
        The window, scale and time of each TCP record, by record number.
    """
    parsed: dict[int, Json] = {}
    for number, (time_us, frame) in enumerate(pcap_records(path), 1):
        tcp = tcp_header(frame, time_us)
        if tcp is not None:
            parsed[number] = tcp
    return parsed
