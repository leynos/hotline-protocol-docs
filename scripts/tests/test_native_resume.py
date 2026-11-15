"""Require native packet, offset-range and independent filesystem evidence."""

import json
import shutil
import struct
from pathlib import Path

import pytest
from verify_native_resume import check_download, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-resume-01"
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


class ResumeTests:
    """Require native resume evidence to match the packets and the filesystem."""

    def test_native_resume_corpus(self) -> None:
        """The retained corpus verifies, with its duplicate and inconsistent cases."""
        result = verify(BATCH)
        assert len(result["cases"]) == 23, "expected the 23 retained resume cases"
        repeated = next(
            c
            for c in result["cases"]
            if c["case"] == "resume-download-duplicate-data-3-4"
        )
        assert repeated["data_bytes"] == 6, "expected six repeated data bytes"
        inconsistent = next(
            c
            for c in result["cases"]
            if c["case"] == "resume-upload-inconsistent-complete"
        )
        assert (inconsistent["data_bytes"], inconsistent["resource_bytes"]) == (
            26,
            322,
        ), "expected the inconsistent upload byte counts"

    def test_shortened_invalid_rflt_window_is_rejected(self) -> None:
        """A shortened pause in an invalid-input window is refused."""
        case = BATCH / "transcripts/resume-download-short-41"
        report = json.loads((case / "report.json").read_text())
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        pause["elapsed_ns"] = prior["elapsed_ns"] + 1
        with pytest.raises(ValueError, match="Short invalid-input window"):
            check_download(case.name, report, {"kind": "resume-no-reply"}, {})

    def test_inconsistent_client_requires_actual_appended_native_bytes(
        self, tmp_path: Path
    ) -> None:
        """A truncated native resumed upload is refused."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        file = directory / "native-files/after/mothra-resume-inconsistent.data"
        file.write_bytes(file.read_bytes()[:13])
        with pytest.raises(ValueError, match="Native resumed DATA differs"):
            verify(directory)

    def test_max_offset_close_requires_native_packet_evidence(
        self, tmp_path: Path
    ) -> None:
        """A capture missing the server's offset-error close is refused."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        report = json.loads(
            (
                directory / "transcripts/resume-download-both-uint32-max/report.json"
            ).read_text()
        )
        port = next(
            e["local_address"][1]
            for e in report["events"]
            if e["event"] == "connect" and e["connection"] == "download"
        )
        path = directory / "guest.pcap"
        omit_server_close(path, 5501, port)
        with pytest.raises(ValueError, match="Missing native offset-error close"):
            verify(directory)
