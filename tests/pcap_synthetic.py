"""Build small synthetic Ethernet/IPv4/TCP captures in memory.

The characterization tests of ``pcap_tcp`` need captures that break one rule at
a time. These helpers assemble the bytes of a classic microsecond capture from
fields, in either byte order, with no file of the retained corpus involved.
"""

import struct
import typing as typ

LITTLE_MAGIC = b"\xd4\xc3\xb2\xa1"
BIG_MAGIC = b"\xa1\xb2\xc3\xd4"
ETHERNET_HEADER = bytes(12) + b"\x08\x00"
SYN = 0x02
ACK = 0x10
RST = 0x04
NS = 0x100


class Header(typ.NamedTuple):
    """The fields of a capture's global header."""

    magic: bytes = LITTLE_MAGIC
    major: int = 2
    minor: int = 4
    snaplen: int = 65535
    linktype: int = 1


def global_header(fields: Header | None = None) -> bytes:
    """Pack a global header in the byte order its magic number announces.

    Parameters
    ----------
    fields : Header | None
        The header fields, default if absent; the magic decides the byte order.

    Returns
    -------
    bytes
        Twenty-four bytes.
    """
    fields = fields or Header()
    order = ">" if fields.magic == BIG_MAGIC else "<"
    body = struct.pack(
        order + "HHIIII",
        fields.major,
        fields.minor,
        0,
        0,
        fields.snaplen,
        fields.linktype,
    )
    return fields.magic + body


class Stamp(typ.NamedTuple):
    """The fields of a packet record's header."""

    seconds: int = 1
    micros: int = 0
    big: bool = False
    original: int | None = None


def record(frame: bytes, stamp: Stamp | None = None) -> bytes:
    """Pack one packet record: the 16-byte header and the frame.

    Parameters
    ----------
    frame : bytes
        The captured frame.
    stamp : Stamp | None
        The header fields, default if absent; ``original`` defaults to the
        frame's length.

    Returns
    -------
    bytes
        The record.
    """
    stamp = stamp or Stamp()
    order = ">" if stamp.big else "<"
    size = len(frame)
    original = size if stamp.original is None else stamp.original
    header = struct.pack(order + "IIII", stamp.seconds, stamp.micros, size, original)
    return header + frame


class Segment(typ.NamedTuple):
    """The fields of a TCP segment inside an IPv4 packet."""

    src: tuple[str, int] = ("10.0.0.1", 1000)
    dst: tuple[str, int] = ("10.0.0.2", 2000)
    sequence: int = 0
    acknowledgement: int = 0
    flags: int = ACK
    payload: bytes = b""
    tcp_options: bytes = b""
    ip_options: bytes = b""
    fragment: int = 0
    protocol: int = 6


def address(text: str) -> bytes:
    """Pack a dotted IPv4 address.

    Returns
    -------
    bytes
        Four bytes.
    """
    return bytes(int(part) for part in text.split("."))


def ip_packet(segment: Segment) -> bytes:
    """Assemble an IPv4 packet that carries a TCP segment.

    Returns
    -------
    bytes
        The packet, with a consistent total length.
    """
    tcp = struct.pack(
        ">HHIIBBHHH",
        segment.src[1],
        segment.dst[1],
        segment.sequence,
        segment.acknowledgement,
        ((20 + len(segment.tcp_options)) // 4) << 4 | (segment.flags >> 8),
        segment.flags & 0xFF,
        0,
        0,
        0,
    )
    tcp += segment.tcp_options + segment.payload
    header_length = 20 + len(segment.ip_options)
    head = struct.pack(
        ">BBHHHBBH",
        0x40 | header_length // 4,
        0,
        header_length + len(tcp),
        0,
        segment.fragment,
        64,
        segment.protocol,
        0,
    )
    head += address(segment.src[0]) + address(segment.dst[0]) + segment.ip_options
    return head + tcp


def tcp_frame(segment: Segment) -> bytes:
    """Wrap a TCP segment in an Ethernet frame.

    Returns
    -------
    bytes
        The frame.
    """
    return ETHERNET_HEADER + ip_packet(segment)


def capture_of(frames: list[bytes], header: Header | None = None) -> bytes:
    """Assemble a whole capture, one second apart per frame, in the header's order.

    Returns
    -------
    bytes
        The capture's bytes.
    """
    header = header or Header()
    big = header.magic == BIG_MAGIC
    body = b"".join(
        record(frame, Stamp(seconds=index + 1, big=big))
        for index, frame in enumerate(frames)
    )
    return global_header(header) + body
