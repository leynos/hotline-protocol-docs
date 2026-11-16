"""Reject overclaims about native HTXF ownership, routing and stored upload bytes."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_htxf import check_case, verify, verify_native_uploads

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]
type Mutation = cabc.Callable[[Report, Report], None]

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-htxf-01"
)
CASES = 18
SHORTENED_NS = 1_000_000_000  # taken off a quiet observation's end time
STRAY_ACTION = 1000  # after every action of the retained case
RESERVED_WORDS_HEX = 4  # the two reserved bytes at the end of the header, in hex


class HtxfTests:
    """Reject overclaims about HTXF ownership, routing and stored upload bytes."""

    @staticmethod
    def check(name: str, mutate: Mutation) -> None:
        """Mutate the retained report and packets of a case, then check them."""
        report = json.loads((BATCH / "transcripts" / name / "report.json").read_text())
        packets = json.loads((BATCH / "packet-reconciliation.json").read_text())[name]
        mutate(report, packets)
        check_case(name, report, packets)

    def test_retained_native_header_and_reference_corpus(self) -> None:
        """The retained corpus verifies with all of its cases."""
        assert len(verify(BATCH)["cases"]) == CASES, "the corpus has eighteen cases"

    def test_reserved_words_are_checked_as_sent(self) -> None:
        """A header whose reserved words were not sent is refused."""

        def mutate(report: Report, _packets: Report) -> None:
            """Zero the reserved words of the header that the data connection sent."""
            sent = report["streams"]["data"]["sent_hex"]
            report["streams"]["data"]["sent_hex"] = (
                sent[:-RESERVED_WORDS_HEX] + "0" * RESERVED_WORDS_HEX
            )

        with pytest.raises(ValueError, match="physical HTXF header differs"):
            self.check("banner-size-one-reserved-1234", mutate)

    def test_duplicate_transport_must_not_repeat_the_banner(self) -> None:
        """A duplicate connection that received the banner is refused."""

        def mutate(report: Report, _packets: Report) -> None:
            """Give the second connection the banner that the first one received."""
            report["streams"]["second"]["received_hex"] = report["streams"]["first"][
                "received_hex"
            ]

        with pytest.raises(
            ValueError, match="Rejected/duplicate connection delivered bytes"
        ):
            self.check("banner-duplicate-after-send", mutate)

    def test_owner_departure_must_precede_stale_attachment(self) -> None:
        """An attachment that did not follow the owner's departure is refused."""

        def mutate(report: Report, _packets: Report) -> None:
            """Move the owner's close after the attachment."""
            event = next(
                e
                for e in report["events"]
                if e["connection"] == "a" and e["event"] == "close"
            )
            event["action"] = STRAY_ACTION

        with pytest.raises(ValueError, match="Owner was not closed before attachment"):
            self.check("download-owner-gone", mutate)

    def test_quiet_window_is_bounded_by_actual_events(self) -> None:
        """A quiet observation shorter than its window is refused."""

        def mutate(report: Report, _packets: Report) -> None:
            """Shorten the quiet observation by a second."""
            event = next(e for e in report["events"] if e["event"] == "quiet")
            event["elapsed_ns"] -= SHORTENED_NS

        with pytest.raises(ValueError, match="Short HTXF quiet observation"):
            self.check("banner-size-one-reserved-1234", mutate)

    def test_upload_data_must_match_the_native_fork(self, tmp_path: Path) -> None:
        """A stored upload whose data differs from the fork is refused."""
        shutil.copytree(BATCH / "native-uploads", tmp_path / "native-uploads")
        (tmp_path / "native-uploads/catalog-11282.data").write_bytes(b"wrong")
        with pytest.raises(ValueError, match="Native upload data differs"):
            verify_native_uploads(tmp_path)

    def test_absent_resource_attribute_is_not_successful_extraction(
        self, tmp_path: Path
    ) -> None:
        """A resource attribute that extracted successfully is refused."""
        shutil.copytree(BATCH / "native-uploads", tmp_path / "native-uploads")
        path = tmp_path / "native-uploads/extraction.json"
        extraction = json.loads(path.read_text())
        extraction["records"][0]["attributes"]["rsrc"]["exit_code"] = 0
        path.write_text(json.dumps(extraction))
        with pytest.raises(
            ValueError, match="Absent resource attribute was not retained"
        ):
            verify_native_uploads(tmp_path)
