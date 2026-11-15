"""Reject incomplete independent observations in the real native corpus."""

import json
import shutil
import struct
from pathlib import Path

import pytest
from verify_native_framing import check_quiet, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-framing-01"
)


def is_tcp_over_ipv4(frame: bytes) -> bool:
    """Tell whether a captured Ethernet frame carries an IPv4 TCP segment.

    Parameters
    ----------
    frame : bytes
        The captured frame, including its Ethernet header.

    Returns
    -------
    bool
        True when the frame is long enough and its headers name TCP over IPv4.
    """
    if len(frame) < 54:
        return False
    return frame[12:14] == b"\x08\x00" and frame[23] == 6


def omit_server_close(path: Path, server_port: int, client_port: int) -> None:
    """Rewrite a capture without the server's FIN or RST packets to the client.

    Parameters
    ----------
    path : pathlib.Path
        The capture file, rewritten in place.
    server_port : int
        The TCP source port of the server whose close packets are removed.
    client_port : int
        The TCP destination port of the client whose close packets are removed.
    """
    raw = path.read_bytes()
    order = "<" if raw[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    result, position = bytearray(raw[:24]), 24
    while position < len(raw):
        size = struct.unpack_from(order + "I", raw, position + 8)[0]
        frame = raw[position + 16 : position + 16 + size]
        omit = False
        if is_tcp_over_ipv4(frame):
            tcp = 14 + (frame[14] & 15) * 4
            omit = (
                int.from_bytes(frame[tcp : tcp + 2], "big") == server_port
                and int.from_bytes(frame[tcp + 2 : tcp + 4], "big") == client_port
                and bool(frame[tcp + 13] & 5)
            )
        if not omit:
            result.extend(raw[position : position + 16 + size])
        position += 16 + size
    path.write_bytes(result)


class FramingTests:
    """Require native framing evidence to show measured silence and real closes."""

    def test_native_framing_matrix(self) -> None:
        """The retained matrix verifies, with its icon case intact."""
        result = verify(BATCH)
        assert len(result["cases"]) == 62, "expected the 62 retained framing cases"
        icon = next(c for c in result["cases"] if c["case"] == "tlv-icon-8000")
        assert icon["emitted_icon_hex"] == "ffff8000", "expected the icon bytes"

    def test_nominal_window_without_measured_silence_is_rejected(self) -> None:
        """A quiet event earlier than its plan's window is refused."""
        case = BATCH / "transcripts/fragment-basic"
        report = json.loads((case / "report.json").read_text())
        quiet = next(e for e in report["events"] if e["event"] == "quiet")
        previous = [e for e in report["events"] if e["action"] < quiet["action"]][-1]
        quiet["elapsed_ns"] = previous["elapsed_ns"] + 1
        plan = json.loads((case / "plan.json").read_text())
        with pytest.raises(ValueError, match="shorter than its plan"):
            check_quiet(report, plan)

    def test_socket_eof_requires_native_close_packets(self, tmp_path: Path) -> None:
        """A capture missing the guest's close packets is refused."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        report = json.loads(
            (directory / "transcripts/data-zero/report.json").read_text()
        )
        port = report["events"][0]["local_address"][1]
        path = directory / "guest.pcap"
        omit_server_close(path, 5500, port)
        with pytest.raises(ValueError, match="Guest did not initiate close"):
            verify(directory)
