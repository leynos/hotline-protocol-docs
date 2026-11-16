"""Read classic microsecond PCAP into IPv4 TCP packets, rejecting incomplete input.

This is the reader behind ``pcap_tcp.read_packets``; it invents no missing bytes.
"""

import struct
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

type Packet = dict[str, typ.Any]

GLOBAL_HEADER_BYTES = 24
RECORD_HEADER_BYTES = 16
ETHERNET_HEADER_BYTES = 14
IPV4_MIN_HEADER_BYTES = 20
TCP_MIN_HEADER_BYTES = 20
BYTE_ORDERS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">"}
EXPECTED_VERSION_AND_LINK = (2, 4, 1)  # PCAP 2.4, Ethernet
MICROSECONDS_PER_SECOND = 1_000_000
MAX_RECORD_BYTES = 65535
ETHERTYPE_IPV4 = b"\x08\x00"
IP_PROTOCOL_TCP = 6
IPV4_VERSION = 4
FRAGMENT_MASK = 0x3FFF  # more-fragments flag and fragment offset


def _check_global_header(header: bytes) -> tuple[str, int]:
    """Validate the 24-byte global header.

    Parameters
    ----------
    header : bytes
        The bytes read from the start of the file.

    Returns
    -------
    tuple[str, int]
        The ``struct`` byte-order prefix and the capture's snap length.

    Raises
    ------
    ValueError
        If the header is short, has another magic number, or is not PCAP 2.4
        Ethernet. The magic number is checked before the version.
    """
    if len(header) != GLOBAL_HEADER_BYTES:
        message = "Truncated PCAP header"
        raise ValueError(message)
    order = BYTE_ORDERS.get(header[:4])
    if order is None:
        message = "Expected classic microsecond PCAP"
        raise ValueError(message)
    _, major, minor, _, _, snaplen, linktype = struct.unpack(order + "IHHIIII", header)
    if (major, minor, linktype) != EXPECTED_VERSION_AND_LINK:
        message = "Expected PCAP2.4 Ethernet"
        raise ValueError(message)
    return order, snaplen


def _invalid_record(micros: int, size: int, original: int, snaplen: int) -> bool:
    """Say whether a record header is outside the accepted bounds.

    Returns
    -------
    bool
        ``True`` for a timestamp of a second or more, a record that was cut
        when captured, or one longer than the snap length or 65535 bytes.
    """
    return any((
        micros >= MICROSECONDS_PER_SECOND,
        size != original,
        size > snaplen,
        size > MAX_RECORD_BYTES,
    ))


def _read_frame(
    source: typ.BinaryIO, raw_header: bytes, order: str, snaplen: int
) -> tuple[int, bytes]:
    """Check one record header and read its frame.

    The header's length and timestamp are checked before the frame is read, so
    a record that is both invalid and cut short is reported as invalid.

    Parameters
    ----------
    source : typing.BinaryIO
        The capture, positioned after the record header.
    raw_header : bytes
        The bytes read as the record header.
    order : str
        The byte-order prefix.
    snaplen : int
        The capture's snap length.

    Returns
    -------
    tuple[int, bytes]
        The timestamp in microseconds and the frame.

    Raises
    ------
    ValueError
        If the header is short, its length or timestamp is invalid, or the
        frame is cut short.
    """
    if len(raw_header) != RECORD_HEADER_BYTES:
        message = "Truncated packet record"
        raise ValueError(message)
    seconds, micros, size, original = struct.unpack(order + "IIII", raw_header)
    if _invalid_record(micros, size, original, snaplen):
        message = "Truncated or invalid packet length/timestamp"
        raise ValueError(message)
    frame = source.read(size)
    if len(frame) != size:
        message = "Truncated packet bytes"
        raise ValueError(message)
    return seconds * MICROSECONDS_PER_SECOND + micros, frame


def _ipv4_of(frame: bytes) -> bytes | None:
    """Return the IPv4 bytes of an Ethernet frame, or ``None`` to skip it.

    Parameters
    ----------
    frame : bytes
        The captured frame.

    Returns
    -------
    bytes | None
        The bytes after the Ethernet header, or ``None`` for a frame that is
        too short or is not IPv4.
    """
    if (
        len(frame) < ETHERNET_HEADER_BYTES
        or frame[12:ETHERNET_HEADER_BYTES] != ETHERTYPE_IPV4
    ):
        return None
    return frame[ETHERNET_HEADER_BYTES:]


def _tcp_of(ip: bytes) -> bytes | None:
    """Return the TCP segment of an IPv4 packet, or ``None`` to skip it.

    The header and size are checked even for a protocol that is then skipped;
    the fragment check applies to TCP only.

    Parameters
    ----------
    ip : bytes
        The bytes after the Ethernet header.

    Returns
    -------
    bytes | None
        The TCP bytes, or ``None`` when the protocol is not TCP.

    Raises
    ------
    ValueError
        If the header or size is invalid, or a TCP packet is fragmented.
    """
    if len(ip) < IPV4_MIN_HEADER_BYTES or ip[0] >> 4 != IPV4_VERSION:
        message = "Invalid IPv4 header"
        raise ValueError(message)
    length = (ip[0] & 15) * 4
    total = int.from_bytes(ip[2:4], "big")
    if not IPV4_MIN_HEADER_BYTES <= length <= total <= len(ip):
        message = "Invalid IPv4 size"
        raise ValueError(message)
    if ip[9] != IP_PROTOCOL_TCP:
        return None
    if int.from_bytes(ip[6:8], "big") & FRAGMENT_MASK:
        message = "Fragmented TCP requires separate IP reassembly"
        raise ValueError(message)
    return ip[length:total]


def _packet_of(index: int, when: int, ip: bytes, tcp: bytes) -> Packet:
    """Describe one TCP segment.

    Parameters
    ----------
    index : int
        The one-based position of the frame in the capture.
    when : int
        The timestamp in microseconds.
    ip : bytes
        The IPv4 packet, for its addresses.
    tcp : bytes
        The TCP segment.

    Returns
    -------
    dict[str, typing.Any]
        The packet's fields.

    Raises
    ------
    ValueError
        If the TCP header is truncated or its data offset is invalid.
    """
    if len(tcp) < TCP_MIN_HEADER_BYTES:
        message = "Truncated TCP header"
        raise ValueError(message)
    offset = (tcp[12] >> 4) * 4
    if not TCP_MIN_HEADER_BYTES <= offset <= len(tcp):
        message = "Invalid TCP size"
        raise ValueError(message)
    return {
        "index": index,
        "timestamp_us": when,
        "src_ip": ".".join(str(b) for b in ip[12:16]),
        "dst_ip": ".".join(str(b) for b in ip[16:20]),
        "src_port": int.from_bytes(tcp[:2], "big"),
        "dst_port": int.from_bytes(tcp[2:4], "big"),
        "sequence": int.from_bytes(tcp[4:8], "big"),
        "acknowledgement": int.from_bytes(tcp[8:12], "big"),
        "flags": tcp[13] | ((tcp[12] & 1) << 8),
        "payload_hex": tcp[offset:].hex(),
    }


def _packet_in(frame: bytes, index: int, when: int) -> Packet | None:
    """Describe the TCP segment in a frame, or return ``None`` to skip it.

    Parameters
    ----------
    frame : bytes
        The captured frame.
    index : int
        The one-based position of the frame in the capture.
    when : int
        The timestamp in microseconds.

    Returns
    -------
    dict[str, typing.Any] | None
        The packet, or ``None`` for a frame that is not IPv4 TCP.
    """
    ip = _ipv4_of(frame)
    if ip is None:
        return None
    tcp = _tcp_of(ip)
    if tcp is None:
        return None
    return _packet_of(index, when, ip, tcp)


def read_packets(path: Path) -> list[Packet]:
    """Read classic microsecond PCAP; reject incomplete or fragmented TCP input.

    Parameters
    ----------
    path : pathlib.Path
        The capture file.

    Returns
    -------
    list[dict[str, typing.Any]]
        One dictionary per IPv4 TCP packet, in capture order. Frames that are
        not IPv4 TCP are skipped but still counted in ``index``.
    """
    packets: list[Packet] = []
    with path.open("rb") as source:
        order, snaplen = _check_global_header(source.read(GLOBAL_HEADER_BYTES))
        index = 0
        while raw_header := source.read(RECORD_HEADER_BYTES):
            when, frame = _read_frame(source, raw_header, order, snaplen)
            index += 1
            packet = _packet_in(frame, index, when)
            if packet is not None:
                packets.append(packet)
    return packets
