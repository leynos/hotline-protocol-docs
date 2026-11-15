"""Require real native prefix, close, buffering and ownership observations."""

import json
import shutil
import struct
import typing as typ
from pathlib import Path

import pytest
from pcap_tcp import direction, read_packets
from verify_native_cleanup import bytes_after, check_download, flow, reply, verify
from verify_native_queues import frame_time

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-cleanup-01"
)
CASES = 10
BASELINE_STREAM_BYTES = 1049073
PARTIAL_PREFIX = 1024
FLIPPED_OFFSET = 200  # a byte inside the cancelled prefix
OWNER_ACK_ID = 21
RETRANSMISSION_DELAY_US = 1000
PCAP_HEADER_BYTES = 24
RECORD_HEADER_BYTES = 16
RECORD_SIZE_OFFSET = 8
MIN_TCP_FRAME_BYTES = 54  # an Ethernet, IPv4 and minimal TCP header
IPV4_PROTOCOL_OFFSET = 23
TCP_PROTOCOL = 6
GUEST_SERVER_PORT = 5501
FIN_OR_RST = 5
ETHERNET_HEADER_BYTES = 14


class CleanupTests:
    """Require real native prefix, close, buffering and ownership observations."""

    @staticmethod
    def load(name: str) -> dict[str, typ.Any]:
        """Load the report of one retained cleanup case.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the case.
        """
        return json.loads((BATCH / "transcripts" / name / "report.json").read_text())

    def test_native_cleanup_corpus(self) -> None:
        """The retained corpus verifies, and its partial case shows the race."""
        result = verify(BATCH)
        assert len(result["cases"]) == CASES, "the corpus has ten cases"
        assert result["baseline_stream_bytes"] == BASELINE_STREAM_BYTES, (
            "the baseline stream differs"
        )
        partial = next(c for c in result["cases"] if c["case"] == "cleanup-partial-1")
        assert partial["application_bytes_read_after_owner_ack"] > PARTIAL_PREFIX, (
            "the application did not read past the prefix after the ACK"
        )
        assert partial["guest_bytes_first_observed_after_owner_request"] > 0, (
            "the guest saw no bytes after the request"
        )
        assert partial["guest_bytes_first_observed_after_owner_ack"] == 0, (
            "the guest saw bytes after the ACK"
        )

    def test_cancelled_bytes_must_match_baseline_prefix(self) -> None:
        """A flipped byte in a cancelled download is not a baseline prefix."""
        report = self.load("cleanup-partial-1")
        baseline = self.load("cleanup-baseline")
        raw = bytearray.fromhex(report["streams"]["reference"]["received_hex"])
        raw[FLIPPED_OFFSET] ^= 1
        report["streams"]["reference"]["received_hex"] = raw.hex()
        with pytest.raises(ValueError, match="not a baseline prefix"):
            check_download(
                report,
                {"variant": "partial-1", "prefix_size": PARTIAL_PREFIX},
                bytes.fromhex(baseline["streams"]["reference"]["received_hex"]),
                {},
                [],
            )

    def test_retransmission_does_not_turn_old_bytes_into_late_delivery(self) -> None:
        """A retransmitted old segment after the ACK is not late delivery."""
        report = self.load("cleanup-partial-1")
        guest = read_packets(BATCH / "guest.pcap")
        packets, client, server = flow(report, "reference", guest)
        ack = frame_time(report, reply(report, "a", OWNER_ACK_ID), guest)
        packet = next(
            p
            for p in direction(packets, server, client)
            if p["payload_hex"] and not p["flags"] & 4
        )
        retransmission = {**packet, "timestamp_us": ack + RETRANSMISSION_DELAY_US}
        count = len(bytes.fromhex(report["streams"]["reference"]["received_hex"]))
        assert (
            bytes_after([*packets, retransmission], server, client, count, ack) == 0
        ), "a retransmission was counted as late delivery"

    def test_successful_captures_do_not_replace_native_file_bytes(
        self, tmp_path: Path
    ) -> None:
        """A changed native data fork is refused although the captures verify."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        file = directory / "native-files/mothra-race-fixture.data"
        raw = bytearray(file.read_bytes())
        raw[0] ^= 1
        file.write_bytes(raw)
        with pytest.raises(ValueError, match="Native cleanup DATA differs"):
            verify(directory)

    @staticmethod
    def is_native_close(frame: bytes, port: int) -> bool:
        """Tell whether a frame is a FIN or RST from the guest server to ``port``.

        Returns
        -------
        bool
            True for a TCP frame from the server port with either flag set.
        """
        if len(frame) < MIN_TCP_FRAME_BYTES:
            return False
        if frame[12:14] != b"\x08\x00" or frame[IPV4_PROTOCOL_OFFSET] != TCP_PROTOCOL:
            return False
        tcp = ETHERNET_HEADER_BYTES + (frame[ETHERNET_HEADER_BYTES] & 15) * 4
        ports = (
            int.from_bytes(frame[tcp : tcp + 2], "big"),
            int.from_bytes(frame[tcp + 2 : tcp + 4], "big"),
        )
        return ports == (GUEST_SERVER_PORT, port) and bool(frame[tcp + 13] & FIN_OR_RST)

    @classmethod
    def without_native_close(cls, raw: bytes, port: int) -> bytes:
        """Drop the guest's FIN and RST packets to ``port`` from a capture.

        Returns
        -------
        bytes
            The capture without those records.
        """
        order = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        result, position = bytearray(raw[:PCAP_HEADER_BYTES]), PCAP_HEADER_BYTES
        while position < len(raw):
            size = struct.unpack_from(order + "I", raw, position + RECORD_SIZE_OFFSET)[
                0
            ]
            frame = raw[
                position + RECORD_HEADER_BYTES : position + RECORD_HEADER_BYTES + size
            ]
            if not cls.is_native_close(frame, port):
                result.extend(raw[position : position + RECORD_HEADER_BYTES + size])
            position += RECORD_HEADER_BYTES + size
        return bytes(result)

    def test_socket_eof_requires_native_close_observation(self, tmp_path: Path) -> None:
        """A capture without the native close is refused."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        report = json.loads(
            (directory / "transcripts/cleanup-partial-1/report.json").read_text()
        )
        port = next(
            e["local_address"][1]
            for e in report["events"]
            if e["event"] == "connect" and e["connection"] == "reference"
        )
        path = directory / "guest.pcap"
        path.write_bytes(self.without_native_close(path.read_bytes(), port))
        with pytest.raises(ValueError, match="Missing native cleanup close"):
            verify(directory)
