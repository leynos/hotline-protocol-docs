"""Check TCP observation analysis against an existing native packet corpus."""

import json
import operator
import typing as typ
from pathlib import Path

import pytest
from pcap_tcp import direction, lifetime, read_packets, stream

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-core-01"
)
LATER_MICROSECONDS = 300_000_000
SEQUENCE_STEP = 100
SEQUENCE_MASK = 0xFFFFFFFF
SYN_SPACING_MICROSECONDS = 1000
SYN_SEQUENCE_STEP = 10

type Endpoint = tuple[str, int]
type Packet = dict[str, typ.Any]


class Flow(typ.NamedTuple):
    """The packets of the first native flow and its two endpoints."""

    packets: list[Packet]
    client: Endpoint
    server: Endpoint


@pytest.fixture
def flow() -> Flow:
    """Read the retained loopback packets and name the first flow's endpoints.

    Returns
    -------
    Flow
        The packets, the client and the server of the first SYN.
    """
    packets = read_packets(BATCH / "loopback.pcap")
    syn = packets[0]
    return Flow(
        packets,
        (syn["src_ip"], syn["src_port"]),
        (syn["dst_ip"], syn["dst_port"]),
    )


class PacketTests:
    """Exercise stream reassembly, lifetime scoping and truncation handling."""

    def test_first_native_flow_matches_both_recorded_streams(self, flow: Flow) -> None:
        """Both directions reassemble to the bytes the transcript recorded."""
        report = json.loads((BATCH / "early-login-and-errors/report.json").read_text())
        expected = report["streams"]["main"]
        sent = stream(flow.packets, flow.client, flow.server).hex()
        received = stream(flow.packets, flow.server, flow.client).hex()
        assert sent == expected["sent_hex"], "expected the recorded client bytes"
        assert received == expected["received_hex"], (
            "expected the recorded server bytes"
        )

    def test_sequence_gap_is_rejected(self, flow: Flow) -> None:
        """A shifted sequence number leaves a gap, which is an error."""
        packets = [dict(p) for p in flow.packets]
        first = next(p for p in packets if p["payload_hex"])
        first["sequence"] += 1
        with pytest.raises(ValueError, match="sequence gap"):
            stream(packets, flow.client, flow.server)

    def test_conflicting_retransmission_is_rejected(self, flow: Flow) -> None:
        """A retransmission that disagrees with the original is an error."""
        duplicate = dict(next(p for p in flow.packets if p["payload_hex"]))
        duplicate["payload_hex"] = "00" + duplicate["payload_hex"][2:]
        with pytest.raises(ValueError, match="Conflicting"):
            stream([*flow.packets, duplicate], flow.client, flow.server)

    def test_reset_diagnostics_do_not_become_application_bytes(
        self, flow: Flow
    ) -> None:
        """Bytes carried by a reset stay in the packet view, not the stream."""
        original = stream(flow.packets, flow.server, flow.client)
        reset = dict(next(p for p in flow.packets if p["src_port"] == flow.server[1]))
        reset.update(flags=4, payload_hex=b"tcp_disconnect".hex())
        with_reset = stream([*flow.packets, reset], flow.server, flow.client)
        assert with_reset == original, "expected the stream to ignore the reset bytes"
        assert bytes.fromhex(reset["payload_hex"]) == b"tcp_disconnect", (
            "expected the reset to keep its diagnostic bytes"
        )

    def test_truncated_packet_is_not_silently_ignored(self, tmp_path: Path) -> None:
        """A capture cut short by one byte is rejected."""
        path = tmp_path / "cut.pcap"
        path.write_bytes((BATCH / "loopback.pcap").read_bytes()[:-1])
        with pytest.raises(ValueError, match="Truncated"):
            read_packets(path)

    def test_reused_socket_tuple_is_scoped_to_its_syn_lifetime(
        self, flow: Flow
    ) -> None:
        """A reused port pair is refused whole but selectable by lifetime."""
        original = sorted(
            direction(flow.packets, flow.client, flow.server)
            + direction(flow.packets, flow.server, flow.client),
            key=operator.itemgetter("timestamp_us"),
        )
        repeated = [
            dict(
                p,
                timestamp_us=p["timestamp_us"] + LATER_MICROSECONDS,
                sequence=(p["sequence"] + SEQUENCE_STEP) & SEQUENCE_MASK,
            )
            for p in original
        ]
        combined = original + repeated
        with pytest.raises(ValueError, match="reused TCP"):
            stream(combined, flow.client, flow.server)
        for first in [original[0], repeated[0]]:
            selected = lifetime(
                combined, flow.client, flow.server, first["timestamp_us"]
            )
            assert stream(selected, flow.client, flow.server) == stream(
                original, flow.client, flow.server
            ), "expected the lifetime to reproduce the original stream"

    def test_ambiguous_syn_lifetimes_are_rejected(self, flow: Flow) -> None:
        """Two SYNs near one socket event cannot be told apart."""
        syn = dict(flow.packets[0])
        duplicate = dict(
            syn,
            timestamp_us=syn["timestamp_us"] + SYN_SPACING_MICROSECONDS,
            sequence=syn["sequence"] + SYN_SEQUENCE_STEP,
        )
        with pytest.raises(ValueError, match="ambiguous SYN"):
            lifetime(
                [*flow.packets, duplicate],
                flow.client,
                flow.server,
                syn["timestamp_us"],
            )
