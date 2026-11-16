"""Characterize ``pcap_tcp`` direction, stream and lifetime before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module. The
packets are plain dictionaries of the shape ``read_packets`` returns, built here
by hand, so no capture file is involved. ``test_characterize_pcap_read.py``
covers the reader.
"""

import typing as typ

import pcap_tcp
import pytest

CHARACTERIZES = "pcap_tcp.py"
CLIENT = ("10.0.0.1", 1000)
SERVER = ("10.0.0.2", 2000)
SYN = 0x02
ACK = 0x10
RST = 0x04
LIMIT = 8 * 1024 * 1024

type Packet = dict[str, typ.Any]


def packet(
    source: tuple[str, int] = CLIENT,
    destination: tuple[str, int] = SERVER,
    **fields: object,
) -> Packet:
    """Build a packet dictionary with defaults for the fields not given.

    Returns
    -------
    dict[str, typing.Any]
        A packet as ``read_packets`` returns it.
    """
    result: Packet = {
        "index": 1,
        "timestamp_us": 0,
        "src_ip": source[0],
        "src_port": source[1],
        "dst_ip": destination[0],
        "dst_port": destination[1],
        "sequence": 0,
        "acknowledgement": 0,
        "flags": ACK,
        "payload_hex": "",
    }
    result.update(fields)
    return result


def data(sequence: int, payload: bytes, **fields: object) -> Packet:
    """Build a client data packet.

    Returns
    -------
    dict[str, typing.Any]
        The packet.
    """
    result = packet(sequence=sequence, payload_hex=payload.hex())
    result.update(fields)
    return result


def refused(packets: list[Packet], message: str) -> None:
    """Require that reassembling the client stream raises this message."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        pcap_tcp.stream(packets, CLIENT, SERVER)


class DirectionTests:
    """Selecting one direction of a flow."""

    def test_only_the_named_endpoints_in_that_order_are_selected(self) -> None:
        """Both ends must match, and the reverse direction does not."""
        forward = packet(sequence=1)
        reverse = packet(SERVER, CLIENT, sequence=2)
        other_port = packet(CLIENT, ("10.0.0.2", 2001), sequence=3)
        other_host = packet(("10.0.0.9", 1000), SERVER, sequence=4)
        packets = [forward, reverse, other_port, other_host]
        assert pcap_tcp.direction(packets, CLIENT, SERVER) == [forward], (
            "expected: both ends must match, and the reverse direction does not"
        )
        assert pcap_tcp.direction(packets, SERVER, CLIENT) == [reverse], (
            "expected: both ends must match, and the reverse direction does not"
        )

    def test_no_match_is_an_empty_list_and_order_is_kept(self) -> None:
        """Selection is a filter, not a sort."""
        packets = [packet(sequence=2), packet(sequence=1)]
        assert pcap_tcp.direction(packets, SERVER, SERVER) == [], (
            "expected: selection is a filter, not a sort"
        )
        assert pcap_tcp.direction(packets, CLIENT, SERVER) == packets, (
            "expected: selection is a filter, not a sort"
        )


class StreamTests:
    """Reassembling one direction into application bytes."""

    def test_a_syn_identified_stream_is_concatenated_in_sequence_order(self) -> None:
        """Out-of-order segments are sorted by their offset."""
        packets = [
            packet(sequence=100, flags=SYN),
            data(104, b"def"),
            data(101, b"abc"),
        ]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"abcdef", (
            "expected: out-of-order segments are sorted by their offset"
        )

    def test_a_syn_that_carries_data_counts_the_syn_as_one_sequence_number(
        self,
    ) -> None:
        """Data on the SYN starts at the SYN's sequence number plus one."""
        packets = [data(100, b"ab", flags=SYN), data(103, b"cd")]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"abcd", (
            "expected: data on the SYN starts at the SYN's sequence number plus one"
        )

    def test_sequence_numbers_wrap_at_two_to_the_thirty_second(self) -> None:
        """A stream that crosses the wrap point reassembles."""
        top = 0xFFFFFFFE
        packets = [
            packet(sequence=top - 1, flags=SYN),
            data(top, b"ab"),
            data(0, b"cd"),
        ]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"abcd", (
            "expected: a stream that crosses the wrap point reassembles"
        )

    def test_a_matching_overlap_and_a_duplicate_are_merged(self) -> None:
        """Retransmissions that agree add nothing; an overlap adds its tail."""
        packets = [
            packet(sequence=0, flags=SYN),
            data(1, b"abcd"),
            data(1, b"abcd"),
            data(3, b"cdef"),
        ]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"abcdef", (
            "expected: retransmissions that agree add nothing; an overlap adds its tail"
        )

    def test_empty_payloads_and_the_other_direction_are_ignored(self) -> None:
        """Pure acknowledgements and the reverse flow do not enter the stream."""
        packets = [
            packet(sequence=0, flags=SYN),
            packet(sequence=1),
            data(1, b"ab"),
            packet(SERVER, CLIENT, sequence=1, payload_hex=b"zz".hex()),
        ]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"ab", (
            "expected: acknowledgements and the reverse flow to stay out"
        )

    def test_an_empty_stream_is_empty_bytes(self) -> None:
        """A SYN alone reassembles to nothing."""
        assert pcap_tcp.stream([packet(flags=SYN)], CLIENT, SERVER) == b"", (
            "expected: a SYN alone reassembles to nothing"
        )

    def test_a_reset_with_a_payload_is_ignored(self) -> None:
        """Bytes on a reset segment stay out of the stream."""
        packets = [
            packet(sequence=0, flags=SYN),
            data(1, b"ab"),
            data(3, b"xx", flags=RST),
        ]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"ab", (
            "expected: bytes on a reset segment stay out of the stream"
        )

    def test_two_syns_with_the_same_sequence_are_one_lifetime(self) -> None:
        """A retransmitted SYN is not a reused port."""
        packets = [
            packet(sequence=5, flags=SYN),
            packet(sequence=5, flags=SYN),
            data(6, b"ab"),
        ]
        assert pcap_tcp.stream(packets, CLIENT, SERVER) == b"ab", (
            "expected: a retransmitted SYN is not a reused port"
        )

    def test_no_syn_is_refused(self) -> None:
        """The stream must be identified by a SYN."""
        refused([data(1, b"ab")], "Missing SYN or reused TCP port lifetime")

    def test_syns_with_different_sequences_are_a_reused_port(self) -> None:
        """Two lifetimes cannot be reassembled together."""
        packets = [packet(sequence=1, flags=SYN), packet(sequence=2, flags=SYN)]
        refused(packets, "Missing SYN or reused TCP port lifetime")

    def test_a_gap_is_refused(self) -> None:
        """A missing byte range between segments."""
        packets = [packet(sequence=0, flags=SYN), data(1, b"ab"), data(5, b"cd")]
        refused(packets, "TCP sequence gap")

    def test_a_gap_at_the_start_is_refused(self) -> None:
        """The first data byte must follow the SYN."""
        refused([packet(sequence=0, flags=SYN), data(3, b"ab")], "TCP sequence gap")

    def test_a_conflicting_retransmission_is_refused(self) -> None:
        """Overlapping bytes must be equal."""
        packets = [packet(sequence=0, flags=SYN), data(1, b"abc"), data(2, b"xy")]
        refused(packets, "Conflicting TCP retransmission")

    def test_a_segment_that_passes_the_bound_is_refused(self) -> None:
        """The analysis bound is eight mebibytes, inclusive."""
        syn = packet(sequence=0, flags=SYN)
        refused([syn, data(1 + LIMIT - 1, b"ab")], "TCP stream exceeds analysis bound")

    def test_a_segment_that_ends_at_the_bound_is_not_refused_for_size(self) -> None:
        """Ending exactly at the bound passes the bound check, then meets the gap."""
        syn = packet(sequence=0, flags=SYN)
        refused([syn, data(1 + LIMIT - 1, b"a")], "TCP sequence gap")

    def test_the_bound_check_comes_before_the_gap_check(self) -> None:
        """A far-away segment is a bound error, not a gap."""
        syn = packet(sequence=0, flags=SYN)
        packets = [syn, data(1, b"ab"), data(LIMIT, b"cc"), data(9, b"d")]
        refused(packets, "TCP stream exceeds analysis bound")

    def test_the_gap_is_found_at_the_lowest_offending_offset(self) -> None:
        """Segments are examined in offset order, so the first fault decides."""
        packets = [
            packet(sequence=0, flags=SYN),
            data(1, b"ab"),
            data(4, b"cd"),
            data(2, b"zz"),
        ]
        refused(packets, "Conflicting TCP retransmission")

    def test_a_missing_syn_is_reported_before_a_reset_or_gap(self) -> None:
        """Identification precedes reassembly."""
        packets = [data(9, b"ab", flags=RST), data(1, b"cd")]
        refused(packets, "Missing SYN or reused TCP port lifetime")


class LifetimeTests:
    """Selecting a unique SYN lifetime near a socket event."""

    @staticmethod
    def flow(start: int, sequence: int = 0) -> list[Packet]:
        """Build a SYN, a SYN-ACK and a data packet of one lifetime.

        Returns
        -------
        list[dict[str, typing.Any]]
            The packets, beginning at ``start`` microseconds.
        """
        return [
            packet(sequence=sequence, flags=SYN, timestamp_us=start),
            packet(SERVER, CLIENT, flags=SYN | ACK, timestamp_us=start + 10),
            data(sequence + 1, b"ab", timestamp_us=start + 20),
        ]

    def test_the_lifetime_holds_both_directions_from_the_syn(self) -> None:
        """Both directions of the flow, in capture order."""
        packets = self.flow(1_000)
        stray = packet(("10.9.9.9", 1), SERVER, timestamp_us=1_005)
        selected = pcap_tcp.lifetime([*packets, stray], CLIENT, SERVER, 1_000)
        assert selected == packets, "expected the flow and not the stray packet"

    def test_the_lifetime_ends_before_the_next_syn_of_another_sequence(self) -> None:
        """The end is exclusive, and a SYN outside the window still sets it."""
        first = self.flow(1_000)
        inside = data(1, b"zz", timestamp_us=8_999_999)
        second = self.flow(9_000_000, sequence=900)
        late = data(1, b"zz", timestamp_us=9_000_000)
        packets = [*first, inside, late, *second]
        selected = pcap_tcp.lifetime(packets, CLIENT, SERVER, 1_000)
        assert selected == [*first, inside], "expected the first lifetime alone"

    def test_the_start_is_inclusive_and_earlier_packets_are_left_out(self) -> None:
        """Packets before the SYN do not belong."""
        packets = self.flow(1_000)
        early = data(0, b"zz", timestamp_us=999)
        selected = pcap_tcp.lifetime([early, *packets], CLIENT, SERVER, 1_000)
        assert selected == packets, "expected only packets from the SYN on"

    def test_a_syn_ack_does_not_start_a_lifetime(self) -> None:
        """SYNs that acknowledge are not counted as first SYNs."""
        packets = [packet(flags=SYN | ACK, sequence=1, timestamp_us=0)]
        with pytest.raises(ValueError, match="Missing or ambiguous SYN lifetime"):
            pcap_tcp.lifetime(packets, CLIENT, SERVER, 0)

    def test_a_syn_exactly_two_seconds_away_is_near(self) -> None:
        """The window is inclusive."""
        packets = self.flow(10_000_000)
        selected = pcap_tcp.lifetime(packets, CLIENT, SERVER, 12_000_000)
        assert selected == packets, "expected the lifetime"

    def test_a_syn_one_microsecond_further_is_not_near(self) -> None:
        """Just outside the window there is no lifetime."""
        packets = self.flow(10_000_000)
        with pytest.raises(ValueError, match="Missing or ambiguous SYN lifetime"):
            pcap_tcp.lifetime(packets, CLIENT, SERVER, 12_000_001)

    def test_two_sequences_near_the_event_are_ambiguous(self) -> None:
        """Two distinct SYN sequences inside the window cannot be told apart."""
        packets = [*self.flow(1_000), *self.flow(2_000, sequence=900)]
        message = r"^Missing or ambiguous SYN lifetime near socket event$"
        with pytest.raises(ValueError, match=message):
            pcap_tcp.lifetime(packets, CLIENT, SERVER, 1_500)

    def test_a_retransmitted_syn_keeps_its_first_timestamp(self) -> None:
        """The start is the first time that sequence's SYN was seen."""
        packets = [
            packet(sequence=0, flags=SYN, timestamp_us=1_000),
            packet(sequence=0, flags=SYN, timestamp_us=1_500),
            data(1, b"ab", timestamp_us=1_200),
        ]
        selected = pcap_tcp.lifetime(packets, CLIENT, SERVER, 1_000)
        assert [p["timestamp_us"] for p in selected] == [1_000, 1_500, 1_200], (
            "expected: the start is the first time that sequence's SYN was seen"
        )

    def test_an_earlier_syn_of_another_sequence_does_not_bound_the_lifetime(
        self,
    ) -> None:
        """Only SYNs after the start end it."""
        earlier = self.flow(500_000_000, sequence=900)
        current = self.flow(3_000_000_000)
        selected = pcap_tcp.lifetime(
            [*earlier, *current], CLIENT, SERVER, 3_000_000_000
        )
        assert selected == current, "expected the current lifetime to run on"
