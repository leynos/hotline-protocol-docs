"""Semantic fault controls for the portable native board witness."""

import hashlib
import json
import shutil
import sys
import typing as typ
from unittest import mock

import native_control_readiness
import pytest
from verify_native_board import CORPUS, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

BOARD_BYTES = 65629  # the stopped board's data fork, as the corpus records it
FLOW_COUNT = 6  # the socket flows that the corpus replays
PCAP_HEADER_BYTES = 24  # a capture that holds no packet
BOARD_BYTE_AFTER_READ = 65536  # the byte after the first 65535 board bytes


class BoardCorpusTests:  # ruff: ignore[too-many-public-methods]  # pylint: disable=too-many-public-methods  # one test per semantic fault, plus the three helpers the original class named
    """Reject each semantic fault that a board corpus copy can carry."""

    @pytest.fixture(autouse=True)
    def setUp(self, tmp_path: Path) -> None:
        """Copy the retained corpus into a fresh temporary directory for a test."""
        self.corpus = tmp_path / CORPUS.name
        shutil.copytree(CORPUS, self.corpus)

    def refresh(self) -> None:
        """Recompute the manifest's file hashes and SHA256SUMS for the copy."""
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        files = {
            str(path.relative_to(self.corpus)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest["files"] = files
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
        )

    def change_json(self, name: str, mutate: cabc.Callable[[typ.Any], object]) -> None:
        """Apply ``mutate`` to the JSON document ``name`` and refresh the hashes."""
        path = self.corpus / name
        value = json.loads(path.read_text())
        mutate(value)
        path.write_text(json.dumps(value, indent=2) + "\n")
        self.refresh()

    def rejected(self, pattern: str) -> None:
        """Require that verification refuses the copy with a message matching it."""
        with pytest.raises(ValueError, match=pattern):
            verify(self.corpus)

    def test_baseline(self) -> None:
        """The retained corpus verifies as it was recorded."""
        result = verify(self.corpus)
        assert result["status"] == "PASS", "the retained corpus does not pass"
        assert result["board_bytes"] == BOARD_BYTES, "the board size differs"
        assert len(result["flows"]) == FLOW_COUNT, "the flow count differs"

    def test_frozen_imports_restore_after_success_and_semantic_failure(self) -> None:
        """The frozen imports are restored after both a pass and a refusal."""
        original = sys.modules["native_control_readiness"]
        original_path = sys.path.copy()
        original_bytecode = sys.dont_write_bytecode
        verify(self.corpus)
        assert sys.modules["native_control_readiness"] is original, "module replaced"
        assert original is native_control_readiness, "module differs from the import"
        with mock.patch("native_control_readiness.login_gate") as mocked:
            assert original.login_gate is mocked, "the patch is not visible"
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report.__setitem__("status", "failed"),
        )
        self.rejected("Finite custom board case")
        assert sys.modules["native_control_readiness"] is original, "module replaced"
        assert sys.path == original_path, "the search path was not restored"
        assert sys.dont_write_bytecode == original_bytecode, "bytecode flag differs"
        with mock.patch("native_control_readiness.login_gate") as mocked:
            assert original.login_gate is mocked, "the patch is not visible"

    def test_board_byte_after_65535_rejected(self) -> None:
        """A board byte beyond the first 65535 is refused by the stored board."""
        path = self.corpus / "raw/stopped/MessageBoard.data"
        data = bytearray(path.read_bytes())
        data[BOARD_BYTE_AFTER_READ] ^= 1
        path.write_bytes(data)
        self.refresh()
        self.rejected("Stopped board DATA")

    def test_wrong_report_segment_rejected(self) -> None:
        """An altered segment in the report is refused against the board."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Alter one byte of the fifth segment of the report."""
            value = report["segments_hex"][4]
            report["segments_hex"][4] = value[:-2] + (
                "00" if value[-2:] != "00" else "ff"
            )

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Board segment|Whole board")

    def test_wrong_recipient_rejected(self) -> None:
        """A waiting-connection update moved to the denied connection is refused."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Move the first eligible update frame to the denied connection."""
            frame = next(
                frame
                for frame in report["frames"]
                if frame["connection"] == "eligible" and frame["type"] == 102
            )
            frame["connection"] = "denied"

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Eligible|Denied|Missing|Raw|frame|102|duplicate")

    def test_post_filler_rejected(self) -> None:
        """An altered filler byte in the tenth post is refused."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Alter the last byte of the tenth post's data."""
            raw = report["post_data_hex"][10]
            report["post_data_hex"][10] = raw[:-2] + (
                "00" if raw[-2:] != "00" else "ff"
            )

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Board segment|Post|filler|request")

    def test_rejected_8193_claim_rejected(self) -> None:
        """A rejected post that claims 8192 bytes is refused as a boundary."""
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report["post_data_hex"].__setitem__(12, "00" * 8192),
        )
        self.rejected("Post boundary")

    def test_read_prefix_rejected(self) -> None:
        """An altered prefix of the rejected read is refused."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Alter the first byte of the rejected read."""
            raw = report["reads"]["12"]
            report["reads"]["12"] = ("00" if raw[:2] != "00" else "ff") + raw[2:]

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Board read/prefix")

    def test_recorded_tail_rejected(self) -> None:
        """An extra recorded byte in a received stream is refused."""

        def mutate(report: dict[str, typ.Any]) -> None:
            """Append one byte to the sender's received stream."""
            report["streams"]["sender"]["received_hex"] += "00"

        self.change_json("raw/coordinator/report.json", mutate)
        self.rejected("Raw stream/event|Received bytes/frame")

    def test_resource_fork_claim_rejected(self) -> None:
        """A stopped board that claims a resource fork is refused."""
        path = self.corpus / "raw/stopped/board-istat.txt"
        path.write_text(
            path.read_text().replace("Resource fork size:\t0", "Resource fork size:\t1")
        )
        self.refresh()
        self.rejected("HFS path, Finder metadata")

    def test_pcap_payload_byte_rejected(self) -> None:
        """An altered payload byte in the namespace capture is refused."""
        path = self.corpus / "raw/lab-namespace.pcap"
        raw = path.read_bytes()
        assert b"TRTPHOTL" in raw, "the payload marker is missing from the capture"
        path.write_bytes(raw.replace(b"TRTPHOTL", b"TRTPH0TL", 1))
        self.refresh()
        self.rejected("PCAP/report bytes|packet/report bytes|tail")

    def test_missing_flow_rejected(self) -> None:
        """A guest capture cut to its header is refused for its missing flows."""
        path = self.corpus / "raw/lab-guest.pcap"
        path.write_bytes(path.read_bytes()[:PCAP_HEADER_BYTES])
        self.refresh()
        self.rejected("packet count|SYN lifetimes")

    def test_primary_syn_rejected(self) -> None:
        """A primary-port capture that holds bridge traffic is refused."""
        path = self.corpus / "raw/primary-syn.pcap"
        path.write_bytes((self.corpus / "raw/lab-namespace.pcap").read_bytes())
        self.refresh()
        self.rejected("primary capture|Primary-port SYN")

    def test_drop_claim_rejected(self) -> None:
        """A recorder that reports a kernel drop is refused."""
        path = self.corpus / "raw/capture-journal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel", 1
            )
        )
        self.refresh()
        self.rejected("Recorder zero-drop")

    def test_stopped_fork_changed_rejected(self) -> None:
        """A changed stopped named fork is refused."""
        path = self.corpus / "raw/stopped/fork-sha256.txt"
        path.write_text(path.read_text().replace("26612ad4", "36612ad4", 1))
        self.refresh()
        self.rejected("Unchanged stopped named fork")

    def test_wrong_catalog_rejected(self) -> None:
        """A stopped board whose Finder type differs is refused."""
        path = self.corpus / "raw/stopped/board-istat.txt"
        path.write_text(path.read_text().replace("TEXT", "BINA", 1))
        self.refresh()
        self.rejected("HFS path, Finder metadata")

    def test_deadline_rejected(self) -> None:
        """A capture receipt with a later deadline is refused."""
        self.change_json(
            "raw/capture-ready.json",
            lambda receipt: receipt.__setitem__(
                "deadline_utc", "2026-11-14T09:23:28+00:00"
            ),
        )
        self.rejected("Actual emulator, capture receipt|fixed deadline")

    def test_source_change_rejected(self) -> None:
        """A changed frozen source file is refused."""
        path = self.corpus / "sources/protocol/native_board_control.py"
        path.write_bytes(path.read_bytes() + b"\n# forged\n")
        self.refresh()
        self.rejected("Frozen source differs")

    def test_incomplete_case_rejected(self) -> None:
        """A coordinator report that did not complete is refused."""
        self.change_json(
            "raw/coordinator/report.json",
            lambda report: report.__setitem__("status", "failed"),
        )
        self.rejected("Finite custom board case")
