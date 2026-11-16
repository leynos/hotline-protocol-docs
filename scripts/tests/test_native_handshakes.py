"""Require observed guest close packets and adequate quiet windows in fixtures."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest
from verify_native_handshakes import verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-transport-01"
)
CASES = 14
TINY_QUIET_SECONDS = 0.01
PCAP_HEADER_BYTES = 24
RECORD_HEADER_BYTES = 16
RECORD_SIZE_OFFSET = 8
MIN_TCP_FRAME_BYTES = 54  # an Ethernet, IPv4 and minimal TCP header
ETHERNET_HEADER_BYTES = 14
IPV4_PROTOCOL_OFFSET = 23
TCP_PROTOCOL = 6
GUEST_SERVER_PORT = 5500
FIN_OR_RST = 5


class HandshakeTests:
    """Require observed guest close packets and adequate quiet windows in fixtures."""

    @pytest.fixture
    def directory(self, tmp_path: Path) -> Path:
        """Copy the retained corpus so that a test can break it.

        Returns
        -------
        pathlib.Path
            The copy.
        """
        target = tmp_path / "fixtures"
        shutil.copytree(BATCH, target)
        return target

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
    def without_native_close(cls, original: bytes, port: int) -> bytes:
        """Drop the guest's FIN and RST packets to ``port`` from a capture.

        Returns
        -------
        bytes
            The capture without those records.
        """
        order = "<" if original[:4] == b"\xd4\xc3\xb2\xa1" else ">"
        result, position = bytearray(original[:PCAP_HEADER_BYTES]), PCAP_HEADER_BYTES
        while position < len(original):
            size = struct.unpack_from(
                order + "I", original, position + RECORD_SIZE_OFFSET
            )[0]
            end = position + RECORD_HEADER_BYTES + size
            if not cls.is_native_close(
                original[position + RECORD_HEADER_BYTES : end], port
            ):
                result.extend(original[position:end])
            position = end
        return bytes(result)

    def test_native_packets_and_socket_streams_agree(self, directory: Path) -> None:
        """The retained corpus verifies, and a wrong magic is reset."""
        result = verify(directory)
        assert len(result["cases"]) == CASES, "the corpus has fourteen cases"
        magic = next(c for c in result["cases"] if c["case"] == "wrong-magic")
        assert magic["guest_server_close_kind"] == "RST", "a wrong magic is reset"
        assert magic["received_bytes"] == 0, "a wrong magic gets no bytes"

    def test_shortened_quiet_window_is_rejected(self, directory: Path) -> None:
        """A quiet window that was shortened in the plan is refused."""
        case = directory / "transcripts/segmented-11"
        plan = json.loads((case / "plan.json").read_text())
        next(s for s in plan["steps"] if s["op"] == "expect_quiet")["timeout"] = (
            TINY_QUIET_SECONDS
        )
        (case / "plan.json").write_text(json.dumps(plan))
        report = json.loads((case / "report.json").read_text())
        report["plan_sha256"] = hashlib.sha256(
            (case / "plan.json").read_bytes()
        ).hexdigest()
        (case / "report.json").write_text(json.dumps(report))
        (case / "checksums.sha256").write_text(
            "".join(
                f"{hashlib.sha256((case / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ["plan.json", "report.json"]
            )
        )
        with pytest.raises(ValueError, match="quiet observation too short"):
            verify(directory)

    def test_socket_eof_without_guest_close_evidence_is_rejected(
        self, directory: Path
    ) -> None:
        """A capture without the guest's close is refused."""
        report = json.loads(
            (directory / "transcripts/wrong-magic/report.json").read_text()
        )
        port = report["events"][0]["local_address"][1]
        path = directory / "guest.pcap"
        path.write_bytes(self.without_native_close(path.read_bytes(), port))
        with pytest.raises(ValueError, match="incomplete guest close"):
            verify(directory)
