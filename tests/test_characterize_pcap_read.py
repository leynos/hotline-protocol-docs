"""Characterize ``pcap_tcp.read_packets`` before ``pcap_tcp`` is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. Captures are
built in memory by ``pcap_synthetic`` and written to temporary files; no
retained capture is opened. Each error message has a capture that breaks that
rule alone, and pairs of faults pin which error is raised first. The stream,
direction and lifetime functions are in ``test_characterize_pcap_streams.py``.
"""

import typing as typ

import pcap_tcp
import pytest
from pcap_synthetic import (
    ACK,
    BIG_MAGIC,
    ETHERNET_HEADER,
    NS,
    SYN,
    Header,
    Segment,
    Stamp,
    capture_of,
    global_header,
    ip_packet,
    record,
    tcp_frame,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

CHARACTERIZES = "pcap_tcp.py"
NANOSECOND_MAGIC = b"\x4d\x3c\xb2\xa1"
KEYS = [
    "index",
    "timestamp_us",
    "src_ip",
    "dst_ip",
    "src_port",
    "dst_port",
    "sequence",
    "acknowledgement",
    "flags",
    "payload_hex",
]


def read(tmp_path: Path, data: bytes) -> list[dict[str, typ.Any]]:
    """Write capture bytes to a temporary file and read them.

    Returns
    -------
    list[dict[str, typing.Any]]
        The packets.
    """
    path = tmp_path / "synthetic.cap"
    path.write_bytes(data)
    return pcap_tcp.read_packets(path)


def refused(tmp_path: Path, data: bytes, message: str) -> None:
    """Require that reading the bytes raises a ``ValueError`` with this message."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        read(tmp_path, data)


def one(segment: Segment) -> bytes:
    """Build a capture of one TCP frame.

    Returns
    -------
    bytes
        The capture.
    """
    return capture_of([tcp_frame(segment)])


class ParsingTests:
    """What a well-formed capture yields."""

    def test_one_segment_yields_one_packet_with_every_field(
        self, tmp_path: Path
    ) -> None:
        """Keys, their order and their values."""
        segment = Segment(
            sequence=7, acknowledgement=9, flags=ACK | 0x08, payload=b"hi"
        )
        data = global_header() + record(
            tcp_frame(segment), Stamp(seconds=3, micros=250)
        )
        packets = read(tmp_path, data)
        expected = {
            "index": 1,
            "timestamp_us": 3_000_250,
            "src_ip": "10.0.0.1",
            "dst_ip": "10.0.0.2",
            "src_port": 1000,
            "dst_port": 2000,
            "sequence": 7,
            "acknowledgement": 9,
            "flags": ACK | 0x08,
            "payload_hex": "6869",
        }
        assert packets == [expected], "expected the one packet"
        assert list(packets[0]) == KEYS, "expected the keys in order"

    def test_both_byte_orders_give_the_same_packets(self, tmp_path: Path) -> None:
        """A big-endian capture reads as its little-endian twin."""
        frames = [tcp_frame(Segment(sequence=n, payload=b"x")) for n in range(3)]
        little = read(tmp_path, capture_of(frames))
        big = read(tmp_path, capture_of(frames, Header(magic=BIG_MAGIC)))
        assert big == little, "expected equal packets"
        assert len(little) == len(frames), "expected one packet per frame"

    def test_an_empty_capture_has_no_packets(self, tmp_path: Path) -> None:
        """A header alone is a valid capture."""
        assert not read(tmp_path, global_header()), "expected no packets"

    def test_the_index_counts_skipped_frames(self, tmp_path: Path) -> None:
        """Frames that are not IPv4 TCP are skipped but numbered."""
        arp = bytes(12) + b"\x08\x06" + bytes(28)
        udp = tcp_frame(Segment(protocol=17))
        runt = b"\x00" * 13
        tcp = tcp_frame(Segment())
        packets = read(tmp_path, capture_of([arp, udp, runt, tcp]))
        assert [p["index"] for p in packets] == [4], "expected index four"

    def test_a_non_tcp_packet_is_skipped_even_when_fragmented(
        self, tmp_path: Path
    ) -> None:
        """The protocol check comes before the fragment check."""
        data = capture_of([tcp_frame(Segment(protocol=17, fragment=0x2000))])
        assert not read(tmp_path, data), "expected the UDP fragment skipped"

    def test_tcp_options_are_excluded_from_the_payload(self, tmp_path: Path) -> None:
        """The data offset decides where the payload starts."""
        segment = Segment(tcp_options=b"\x01\x01\x01\x01", payload=b"ab")
        assert read(tmp_path, one(segment))[0]["payload_hex"] == "6162", (
            "expected: the data offset decides where the payload starts"
        )

    def test_ip_options_are_skipped(self, tmp_path: Path) -> None:
        """The header length decides where the TCP header starts."""
        segment = Segment(ip_options=b"\x01\x01\x01\x01", payload=b"ab", sequence=5)
        packet = read(tmp_path, one(segment))[0]
        assert (packet["payload_hex"], packet["sequence"]) == ("6162", 5), (
            "expected: the header length decides where the TCP header starts"
        )

    def test_link_padding_after_the_ip_total_length_is_ignored(
        self, tmp_path: Path
    ) -> None:
        """Bytes after the IP total length do not enter the payload."""
        frame = tcp_frame(Segment(payload=b"ab")) + b"\x00\x00\x00"
        assert read(tmp_path, capture_of([frame]))[0]["payload_hex"] == "6162", (
            "expected: bytes after the IP total length do not enter the payload"
        )

    def test_the_ns_bit_is_the_ninth_flag_bit(self, tmp_path: Path) -> None:
        """The low bit of the data-offset byte becomes bit eight of the flags."""
        assert read(tmp_path, one(Segment(flags=SYN | NS)))[0]["flags"] == SYN | NS, (
            "expected: the data-offset low bit to become flag bit eight"
        )

    def test_the_dont_fragment_bit_is_not_a_fragment(self, tmp_path: Path) -> None:
        """Only the more-fragments bit and the offset are refused."""
        packets = read(tmp_path, one(Segment(fragment=0x4000)))
        assert len(packets) == 1, "expected the packet to be accepted"

    def test_timestamps_are_microseconds_since_the_epoch(self, tmp_path: Path) -> None:
        """Seconds times a million plus the microseconds."""
        data = global_header() + record(
            tcp_frame(Segment()), Stamp(seconds=2, micros=999999)
        )
        assert read(tmp_path, data)[0]["timestamp_us"] == 2_999_999, (
            "expected: seconds times a million plus the microseconds"
        )

    def test_a_missing_file_is_a_file_not_found_error(self, tmp_path: Path) -> None:
        """The path is opened first."""
        with pytest.raises(FileNotFoundError):
            pcap_tcp.read_packets(tmp_path / "absent.cap")


class GlobalHeaderTests:
    """The global header is checked before any record."""

    @pytest.mark.parametrize("size", [0, 1, 23])
    def test_a_short_header_is_truncated(self, tmp_path: Path, size: int) -> None:
        """Fewer than 24 bytes."""
        refused(tmp_path, global_header()[:size], "Truncated PCAP header")

    @pytest.mark.parametrize(
        "magic", [NANOSECOND_MAGIC, b"\x00\x00\x00\x00", b"\x0a\x0d\x0d\x0a"]
    )
    def test_another_magic_number_is_refused(
        self, tmp_path: Path, magic: bytes
    ) -> None:
        """Only the two classic microsecond magics are accepted."""
        refused(
            tmp_path,
            global_header(Header(magic=magic)),
            "Expected classic microsecond PCAP",
        )

    @pytest.mark.parametrize(
        "fields",
        [Header(major=1), Header(minor=3), Header(linktype=0), Header(linktype=101)],
    )
    def test_another_version_or_link_type_is_refused(
        self, tmp_path: Path, fields: Header
    ) -> None:
        """Version 2.4 and Ethernet only."""
        refused(tmp_path, global_header(fields), "Expected PCAP2.4 Ethernet")

    def test_the_magic_check_comes_before_the_version_check(
        self, tmp_path: Path
    ) -> None:
        """A bad magic with a bad version is a magic error."""
        data = global_header(Header(magic=NANOSECOND_MAGIC, major=9))
        refused(tmp_path, data, "Expected classic microsecond PCAP")

    def test_the_header_is_checked_before_any_record_is_read(
        self, tmp_path: Path
    ) -> None:
        """A bad header followed by a bad record is a header error."""
        data = global_header(Header(linktype=0)) + b"\x00" * 5
        refused(tmp_path, data, "Expected PCAP2.4 Ethernet")


class RecordTests:
    """Each record's header and bytes are checked before its frame is parsed."""

    def test_a_partial_record_header_is_truncated(self, tmp_path: Path) -> None:
        """Fewer than 16 bytes where a record header should be."""
        refused(tmp_path, global_header() + b"\x00" * 15, "Truncated packet record")

    @pytest.mark.parametrize(
        ("micros", "original", "snaplen"),
        [
            (1_000_000, None, 65535),
            (0, 99, 65535),
            (0, None, 10),
        ],
    )
    def test_an_invalid_length_or_timestamp_is_refused(
        self, tmp_path: Path, micros: int, original: int | None, snaplen: int
    ) -> None:
        """Microseconds of a second or more, a cut record, or a record over snaplen."""
        frame = tcp_frame(Segment())
        data = global_header(Header(snaplen=snaplen)) + record(
            frame, Stamp(micros=micros, original=original)
        )
        refused(tmp_path, data, "Truncated or invalid packet length/timestamp")

    def test_a_record_over_65535_bytes_is_refused(self, tmp_path: Path) -> None:
        """The size ceiling applies even when snaplen allows it."""
        header = Header(snaplen=0xFFFFFFFF)
        data = global_header(header) + record(b"\x00" * 65536)
        refused(tmp_path, data, "Truncated or invalid packet length/timestamp")

    def test_a_record_of_exactly_65535_bytes_is_read_and_skipped(
        self, tmp_path: Path
    ) -> None:
        """The ceiling is inclusive; a non-IP frame of that size is skipped."""
        assert not read(tmp_path, global_header() + record(b"\x00" * 65535)), (
            "expected: the ceiling is inclusive; a non-IP frame of that size is skipped"
        )

    def test_missing_frame_bytes_are_truncated(self, tmp_path: Path) -> None:
        """A record header that promises more than the file holds."""
        data = global_header() + record(tcp_frame(Segment()))[:-1]
        refused(tmp_path, data, "Truncated packet bytes")

    def test_the_length_check_comes_before_the_byte_read(self, tmp_path: Path) -> None:
        """An over-snaplen record that is also cut short is a length error."""
        frame = tcp_frame(Segment())
        data = global_header(Header(snaplen=10)) + record(frame)[:-1]
        refused(tmp_path, data, "Truncated or invalid packet length/timestamp")

    def test_an_error_in_a_later_record_discards_earlier_packets(
        self, tmp_path: Path
    ) -> None:
        """Nothing is returned when any record is bad."""
        good = record(tcp_frame(Segment()))
        data = global_header() + good + good[:20]
        refused(tmp_path, data, "Truncated packet bytes")


class FrameTests:
    """The IPv4 and TCP headers of a record's frame."""

    @staticmethod
    def frame(ip: bytes) -> bytes:
        """Wrap IP bytes in an IPv4 Ethernet header.

        Returns
        -------
        bytes
            The frame.
        """
        return ETHERNET_HEADER + ip

    def test_a_short_ip_header_is_invalid(self, tmp_path: Path) -> None:
        """Fewer than 20 bytes after the Ethernet header."""
        data = capture_of([self.frame(b"\x45" + b"\x00" * 18)])
        refused(tmp_path, data, "Invalid IPv4 header")

    def test_another_ip_version_is_invalid(self, tmp_path: Path) -> None:
        """The version nibble must be four."""
        packet = bytearray(ip_packet(Segment()))
        packet[0] = 0x65
        refused(
            tmp_path, capture_of([self.frame(bytes(packet))]), "Invalid IPv4 header"
        )

    def test_the_header_check_comes_before_the_protocol_skip(
        self, tmp_path: Path
    ) -> None:
        """A malformed IPv4 header is refused even when the protocol is UDP."""
        packet = bytearray(ip_packet(Segment(protocol=17)))
        packet[0] = 0x65
        refused(
            tmp_path, capture_of([self.frame(bytes(packet))]), "Invalid IPv4 header"
        )

    @pytest.mark.parametrize("nibble", [0, 4])
    def test_a_header_length_under_twenty_is_an_invalid_size(
        self, tmp_path: Path, nibble: int
    ) -> None:
        """IHL below five."""
        packet = bytearray(ip_packet(Segment()))
        packet[0] = 0x40 | nibble
        refused(tmp_path, capture_of([self.frame(bytes(packet))]), "Invalid IPv4 size")

    def test_a_total_length_under_the_header_length_is_an_invalid_size(
        self, tmp_path: Path
    ) -> None:
        """Total length below the header length."""
        packet = bytearray(ip_packet(Segment()))
        packet[2:4] = (19).to_bytes(2, "big")
        refused(tmp_path, capture_of([self.frame(bytes(packet))]), "Invalid IPv4 size")

    def test_a_total_length_over_the_bytes_present_is_an_invalid_size(
        self, tmp_path: Path
    ) -> None:
        """Total length beyond the frame."""
        packet = bytearray(ip_packet(Segment()))
        packet[2:4] = (len(packet) + 1).to_bytes(2, "big")
        refused(tmp_path, capture_of([self.frame(bytes(packet))]), "Invalid IPv4 size")

    @pytest.mark.parametrize("fragment", [0x2000, 0x0001, 0x1FFF])
    def test_a_fragmented_tcp_packet_is_refused(
        self, tmp_path: Path, fragment: int
    ) -> None:
        """More-fragments or any offset."""
        refused(
            tmp_path,
            one(Segment(fragment=fragment)),
            "Fragmented TCP requires separate IP reassembly",
        )

    def test_a_tcp_segment_under_twenty_bytes_is_truncated(
        self, tmp_path: Path
    ) -> None:
        """The TCP header must be complete."""
        packet = bytearray(ip_packet(Segment()))[:30]
        packet[2:4] = (30).to_bytes(2, "big")
        refused(
            tmp_path, capture_of([self.frame(bytes(packet))]), "Truncated TCP header"
        )

    @pytest.mark.parametrize("nibble", [0, 4, 6])
    def test_a_bad_tcp_data_offset_is_an_invalid_size(
        self, tmp_path: Path, nibble: int
    ) -> None:
        """Below five words, or beyond the segment."""
        packet = bytearray(ip_packet(Segment()))
        packet[20 + 12] = nibble << 4
        refused(tmp_path, capture_of([self.frame(bytes(packet))]), "Invalid TCP size")

    def test_the_fragment_check_comes_before_the_tcp_header_check(
        self, tmp_path: Path
    ) -> None:
        """A fragment too short for a TCP header is a fragment error."""
        packet = bytearray(ip_packet(Segment(fragment=0x2000)))[:30]
        packet[2:4] = (30).to_bytes(2, "big")
        message = "Fragmented TCP requires separate IP reassembly"
        refused(tmp_path, capture_of([self.frame(bytes(packet))]), message)
