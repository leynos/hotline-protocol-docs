"""Check folder direction/state distinctions and independent native fork state."""

import json
import shutil
from pathlib import Path

import pytest
from native_folder_clock_checks import upload_clock
from native_folder_stream import Cursor, descriptor, download
from pcap_tcp import read_packets
from verify_native_folders import check_upload, verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-folder-01"
)
CASE_COUNT = 17
FULL_AGGREGATE_BYTES = 652
FULL_FILE_STREAM_BYTES = 1148
FULL_ITEM_COUNT = 5
PARTIAL_BEFORE_RESOURCE_BYTES = 5
PARTIAL_AFTER_RESOURCE_BYTES = 317
SHORTENED_PAUSE_NANOSECONDS = 1


class FolderTests:
    """Check folder direction/state distinctions and independent native fork state."""

    def test_native_folder_corpus(self) -> None:
        """The retained corpus verifies with its case count, sizes and partial bytes."""
        result = verify(BATCH)
        assert len(result["cases"]) == CASE_COUNT, "expected seventeen folder cases"
        full = next(c for c in result["cases"] if c["case"] == "folder-download-full")
        assert (
            full["aggregate_bytes"],
            full["file_stream_bytes"],
            full["item_count"],
        ) == (
            FULL_AGGREGATE_BYTES,
            FULL_FILE_STREAM_BYTES,
            FULL_ITEM_COUNT,
        ), "the full download aggregate differs"
        assert all(i["path"] for i in full["items"]), "every item has a path"
        assert (
            result["native_files"]["before"]["partial_resource_bytes"]
            == PARTIAL_BEFORE_RESOURCE_BYTES
        ), "the partial resource before the flush differs"
        assert (
            result["native_files"]["after"]["partial_resource_bytes"]
            == PARTIAL_AFTER_RESOURCE_BYTES
        ), "the partial resource after the flush differs"

    def test_final_file_does_not_inherit_directory_final_control(self) -> None:
        """A file that ends an upload is not given the directory's final control."""
        report = json.loads(
            (BATCH / "transcripts/folder-upload-fresh/report.json").read_text()
        )
        report["streams"]["folder"]["received_hex"] += "0003"
        with pytest.raises(ValueError, match="File-ending next-control differs"):
            check_upload(
                "folder-upload-fresh",
                report,
                {"folder": {"guest_server_initiated_close": True}},
            )

    def test_truncated_descriptor_and_file_body_are_rejected(self) -> None:
        """A truncated descriptor and a truncated file body are both refused."""
        with pytest.raises(ValueError, match="Truncated folder stream"):
            descriptor(Cursor(bytes.fromhex("ffff00000001000005616c706861")))
        report = json.loads(
            (BATCH / "transcripts/folder-download-full/report.json").read_text()
        )
        sent = bytes.fromhex(report["streams"]["folder"]["sent_hex"])
        received = bytes.fromhex(report["streams"]["folder"]["received_hex"])
        with pytest.raises(ValueError, match="Truncated folder stream"):
            download(sent, received[:-1])

    def test_resume_wire_success_requires_original_partial_native_bytes(
        self, tmp_path: Path
    ) -> None:
        """A wire-level resume success is refused when the partial bytes are wrong."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        file = directory / "native-files/before/mothra-folder-partial__part.rsrc"
        file.write_bytes(file.read_bytes()[:-1])
        with pytest.raises(ValueError, match="Native folder MACR differs"):
            verify(directory)

    def test_declared_folder_delay_requires_measured_pause_evidence(self) -> None:
        """A declared folder delay whose measured pause is short is refused."""
        case = BATCH / "transcripts/folder-upload-late-attachment"
        report = json.loads((case / "report.json").read_text())
        plan = json.loads((case / "plan.json").read_text())
        pause = next(e for e in report["events"] if e["event"] == "pause")
        prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
        pause["elapsed_ns"] = prior["elapsed_ns"] + SHORTENED_PAUSE_NANOSECONDS
        with pytest.raises(ValueError, match="Shortened folder timing pause"):
            upload_clock(
                case.name, report, plan, read_packets(BATCH / "timers-guest.pcap")
            )
