"""Reject metadata omission, physical/resolved alias confusion and overclaims."""

import copy
import json
import typing as typ
from pathlib import Path

import pytest
from native_alias_cases import create, information
from verify_native_aliases import (
    creation,
    download,
    listing_views,
    metadata,
    transfer_quiet,
    verify,
)
from verify_native_auth import reply

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-alias-01"
)
COMPLETED_REPORTS = 44
PAIRED_CONNECTIONS = 66
POSITIVE_AFTER = 3
QUIET_SHORTFALL_NS = 2_000_000_000
PHYSICAL_RESOURCE_SIZE = 546


class AliasTests:
    """Reject metadata omission, physical/resolved alias confusion and overclaims."""

    def report(self, key: str) -> Report:
        """Load the retained report of one case.

        Returns
        -------
        dict[str, typing.Any]
            The report as the capture recorded it.
        """
        return json.loads((BATCH / key / "report.json").read_text())

    def change_field(
        self, report: Report, identifier: int, field: int, value: bytes | None
    ) -> None:
        """Replace one field of a reply, or remove it when ``value`` is None."""
        frame = reply(report, identifier)
        item = next(v for v in frame["fields"] if v["id"] == field)
        if value is None:
            frame["fields"].remove(item)
        else:
            item["hex"] = value.hex()

    def test_full_alias_corpus_has_paired_socket_and_positive_fork_evidence(
        self,
    ) -> None:
        """The retained corpus verifies with its reports, connections and catalogue."""
        result = verify(BATCH)
        assert (result["completed_reports"], result["paired_connections"]) == (
            COMPLETED_REPORTS,
            PAIRED_CONNECTIONS,
        ), "expected 44 completed reports over 66 paired connections"
        assert result["catalogue"]["positive_after"] == POSITIVE_AFTER, (
            "expected three positive records after cleanup"
        )

    def test_zero_tags_are_present_four_byte_values(self) -> None:
        """A zero-tag field that is omitted is a presence failure."""
        report = self.report("info/zero-tags")
        self.change_field(report, 10, 213, None)
        with pytest.raises(ValueError, match="presence"):
            metadata(report, "zero-tags", b"zero-tags")

    def test_empty_file_has_present_two_byte_zero_size(self) -> None:
        """A four-byte size for an empty file is a bytes failure."""
        report = self.report("info/empty-file")
        self.change_field(report, 10, 207, bytes(4))
        with pytest.raises(ValueError, match="bytes"):
            metadata(report, "empty-file", b"empty")

    def test_directory_has_no_file_size(self) -> None:
        """A directory that reports a file size is a presence failure."""
        report = self.report("info/ordinary-directory")
        reply(report, 10)["fields"].append({"id": 207, "hex": "0000"})
        with pytest.raises(ValueError, match="presence"):
            metadata(report, "ordinary-directory", b"dir")

    def test_unattached_alias_has_no_dates(self) -> None:
        """An unattached alias that reports dates is a presence failure."""
        report = self.report("info/self-after-create")
        reply(report, 10)["fields"].append({"id": 208, "hex": bytes(8).hex()})
        with pytest.raises(ValueError, match="presence"):
            metadata(report, "self-after-create", b"self")

    def test_file_alias_size_is_resolved_forks_not_physical_resource_size(
        self,
    ) -> None:
        """An alias reporting the physical resource size is a bytes failure."""
        report = self.report("info/file-alias")
        self.change_field(report, 10, 207, PHYSICAL_RESOURCE_SIZE.to_bytes(2, "big"))
        with pytest.raises(ValueError, match="bytes"):
            metadata(report, "file-alias", b"file")

    def test_derived_alias_info_retains_alias_name(self) -> None:
        """A derived alias that reports its target's name is a bytes failure."""
        report = self.report("info/derived-alias")
        self.change_field(report, 10, 201, b"file")
        with pytest.raises(ValueError, match="bytes"):
            metadata(report, "derived-alias", b"derived-link")

    def test_ordinary_file_collision_can_succeed(self) -> None:
        """A collision that returns an error instead of an ACK is rejected."""
        report = self.report("create/file-collision")
        reply(report, 12)["error"] = 1
        with pytest.raises(ValueError, match="ACK"):
            creation(report, create()["file-collision"][1])

    def test_permission_error_cannot_be_an_empty_ack(self) -> None:
        """A permission refusal with no error field is an error-outcome failure."""
        report = self.report("create/permission-new")
        reply(report, 12)["fields"] = []
        with pytest.raises(ValueError, match="error outcome"):
            creation(report, create()["permission-new"][1])

    def test_file_download_uses_source_fork_bytes(self) -> None:
        """A download whose data fork is not the source's bytes is rejected."""
        report = self.report("download/file-alias")
        stream = report["streams"]["transfer"]
        stream["received_hex"] = stream["received_hex"].replace(
            b"alias-target".hex(), b"wrong-target".hex()
        )
        with pytest.raises(ValueError, match="data fork"):
            download(report)

    def test_listing_order_is_retained_exactly(self) -> None:
        """A reversed root listing is rejected for its order and name bytes."""
        keys = [
            "info/ordinary-file",
            "create/live-file",
            "info/file-alias",
            "info/file-chain",
            "info/derived-alias",
            "create/file-collision",
        ]
        reports = {key: self.report(key) for key in keys}
        listing_views(reports)
        changed = copy.deepcopy(reports)
        reply(changed["info/ordinary-file"], 11)["fields"].reverse()
        with pytest.raises(ValueError, match="order/name"):
            listing_views(changed)

    def test_transfer_quiet_observation_is_measured(self) -> None:
        """A quiet observation shorter than the interval is rejected."""
        report = self.report("download/file-alias")
        plan = json.loads((BATCH / "download/file-alias/plan.json").read_text())
        event = next(e for e in report["events"] if e["event"] == "quiet")
        event["elapsed_ns"] -= QUIET_SHORTFALL_NS
        with pytest.raises(ValueError, match="missing/short"):
            transfer_quiet(report, plan)

    def test_unknown_description_is_raw_tag(self) -> None:
        """An unknown type description must be the raw tag, not a name."""
        report = self.report("info/unknown-tags")
        self.change_field(report, 10, 205, b"Unknown File")
        with pytest.raises(ValueError, match="bytes"):
            metadata(report, "unknown-tags", b"unknown-tags")

    def test_all_prepared_metadata_kinds_have_distinct_captured_reports(self) -> None:
        """Every prepared metadata kind has exactly one captured report."""
        assert set(information()) == {p.name for p in (BATCH / "info").iterdir()}, (
            "expected one captured report for each prepared metadata kind"
        )
