"""Keep native banner loading distinct from metadata, file storage and reset scope."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_banner_formats import content
from verify_native_banner_formats import (
    check_format,
    check_recovery,
    verify,
    verify_native_files,
)

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-banner-02"
)


def load_report(name: str) -> dict[str, typ.Any]:
    """Load the report of one retained banner-format case.

    Parameters
    ----------
    name : str
        The name of the case directory under ``transcripts``.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``report.json`` of that case.
    """
    return json.loads((BATCH / "transcripts" / name / "report.json").read_text())


class BannerFormatTests:
    """Require format, recovery and reset evidence to stay within its own scope."""

    def test_native_format_recovery_and_reset_corpus(self) -> None:
        """The retained corpus verifies, with its text, recovery and reset cases."""
        result = verify(BATCH)
        assert len(result["formats"]) == 8, "expected the eight retained formats"
        text = next(c for c in result["formats"] if c["format"] == "text-conversion")
        assert (text["native_file_bytes"], text["received_bytes"]) == (
            43,
            42,
        ), "expected the text conversion byte counts"
        assert result["recovery"]["received_bytes"] == 58, "expected 58 recovered bytes"
        assert result["packet_reconciliation"]["format-empty"]["observer"][
            "guest_server_initiated_close"
        ], "expected the empty format to be closed by the guest"

    def test_text_loader_output_is_not_the_original_native_fork(self) -> None:
        """Text loader output in place of the native fork payload is refused."""
        report = load_report("format-text-conversion")
        report["streams"]["banner"]["received_hex"] = content("text-conversion").hex()
        with pytest.raises(ValueError, match="payload differs"):
            check_format("text-conversion", report)

    def test_zero_type_can_transfer_without_a_metadata_notification(self) -> None:
        """A zero-type transfer that gains a metadata notification is refused."""
        report = load_report("format-zero-type")
        jpeg = load_report("format-jpeg")
        report["frames"].extend(f for f in jpeg["frames"] if f["type"] == 122)
        with pytest.raises(ValueError, match="metadata eligibility differs"):
            check_format("zero-type", report)

    def test_present_empty_buffer_still_has_metadata(self) -> None:
        """A present empty buffer without metadata is refused."""
        report = load_report("format-empty")
        report["frames"] = [f for f in report["frames"] if f["type"] != 122]
        with pytest.raises(ValueError, match="metadata eligibility differs"):
            check_format("empty", report)

    def test_restoration_requires_a_positive_protocol_phase(self) -> None:
        """A restored phase without GIF metadata is refused."""
        report = load_report("phase-checked-recovery")
        report["frames"] = [
            f
            for f in report["frames"]
            if not (f["connection"] == "restored" and f["type"] == 122)
        ]
        plan = json.loads(
            (BATCH / "transcripts/phase-checked-recovery/plan.json").read_text()
        )
        with pytest.raises(ValueError, match="Restored phase lacks GIF metadata"):
            check_recovery(report, plan)

    def test_recovery_pause_duration_is_observed(self) -> None:
        """A recovery pause shortened by one second is refused."""
        report = load_report("phase-checked-recovery")
        plan = json.loads(
            (BATCH / "transcripts/phase-checked-recovery/plan.json").read_text()
        )
        event = next(
            e
            for e in report["events"]
            if e["event"] == "pause" and plan["steps"][e["action"]]["seconds"] == 30
        )
        event["elapsed_ns"] -= 1_000_000_000
        with pytest.raises(ValueError, match="Shortened recovery phase pause"):
            check_recovery(report, plan)

    def test_disappearance_is_after_the_owner_banner_advertisement(self) -> None:
        """Banner metadata missing from the main connection is refused."""
        report = load_report("phase-checked-recovery")
        plan = json.loads(
            (BATCH / "transcripts/phase-checked-recovery/plan.json").read_text()
        )
        assert plan["expectation"]["initial_completion"] == "delayed", (
            "expected the initial completion to be delayed"
        )
        report["frames"] = [
            f
            for f in report["frames"]
            if not (f["connection"] == "main" and f["type"] == 122)
        ]
        with pytest.raises(ValueError, match="Initial delayed banner metadata differs"):
            check_recovery(report, plan)

    def test_native_finder_type_is_checked_separately(self, tmp_path: Path) -> None:
        """A changed native Finder type is refused by the file verifier."""
        for name in [
            "native-format-files",
            "native-text-file",
            "native-empty-file",
        ]:
            shutil.copytree(BATCH / name, tmp_path / name)
        file = tmp_path / "native-text-file/catalog-11259.stat.txt"
        file.write_text(file.read_text().replace("54455854  TEXT", "47494666  GIFf"))
        with pytest.raises(ValueError, match="native Finder type differs"):
            verify_native_files(tmp_path)
