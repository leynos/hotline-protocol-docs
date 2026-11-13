"""Reject metadata omission, physical/resolved alias confusion and overclaims."""

import copy
import json
import unittest
from pathlib import Path

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

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-alias-01"
)


class AliasTests(unittest.TestCase):
    def report(self, key: str) -> dict:
        return json.loads((BATCH / key / "report.json").read_text())

    def change_field(
        self, report: dict, identifier: int, field: int, value: bytes | None
    ) -> None:
        frame = reply(report, identifier)
        item = next(v for v in frame["fields"] if v["id"] == field)
        if value is None:
            frame["fields"].remove(item)
        else:
            item["hex"] = value.hex()

    def test_full_alias_corpus_has_paired_socket_and_positive_fork_evidence(
        self,
    ) -> None:
        result = verify(BATCH)
        self.assertEqual(
            (result["completed_reports"], result["paired_connections"]), (44, 66)
        )
        self.assertEqual(result["catalogue"]["positive_after"], 3)

    def test_zero_tags_are_present_four_byte_values(self) -> None:
        report = self.report("info/zero-tags")
        self.change_field(report, 10, 213, None)
        with self.assertRaisesRegex(ValueError, "presence"):
            metadata(report, "zero-tags", b"zero-tags")

    def test_empty_file_has_present_two_byte_zero_size(self) -> None:
        report = self.report("info/empty-file")
        self.change_field(report, 10, 207, bytes(4))
        with self.assertRaisesRegex(ValueError, "bytes"):
            metadata(report, "empty-file", b"empty")

    def test_directory_has_no_file_size(self) -> None:
        report = self.report("info/ordinary-directory")
        reply(report, 10)["fields"].append({"id": 207, "hex": "0000"})
        with self.assertRaisesRegex(ValueError, "presence"):
            metadata(report, "ordinary-directory", b"dir")

    def test_unattached_alias_has_no_dates(self) -> None:
        report = self.report("info/self-after-create")
        reply(report, 10)["fields"].append({"id": 208, "hex": bytes(8).hex()})
        with self.assertRaisesRegex(ValueError, "presence"):
            metadata(report, "self-after-create", b"self")

    def test_file_alias_size_is_resolved_forks_not_physical_resource_size(self) -> None:
        report = self.report("info/file-alias")
        self.change_field(report, 10, 207, (546).to_bytes(2, "big"))
        with self.assertRaisesRegex(ValueError, "bytes"):
            metadata(report, "file-alias", b"file")

    def test_derived_alias_info_retains_alias_name(self) -> None:
        report = self.report("info/derived-alias")
        self.change_field(report, 10, 201, b"file")
        with self.assertRaisesRegex(ValueError, "bytes"):
            metadata(report, "derived-alias", b"derived-link")

    def test_ordinary_file_collision_can_succeed(self) -> None:
        report = self.report("create/file-collision")
        reply(report, 12)["error"] = 1
        with self.assertRaisesRegex(ValueError, "ACK"):
            creation(report, create()["file-collision"][1])

    def test_permission_error_cannot_be_an_empty_ack(self) -> None:
        report = self.report("create/permission-new")
        reply(report, 12)["fields"] = []
        with self.assertRaisesRegex(ValueError, "error outcome"):
            creation(report, create()["permission-new"][1])

    def test_file_download_uses_source_fork_bytes(self) -> None:
        report = self.report("download/file-alias")
        stream = report["streams"]["transfer"]
        stream["received_hex"] = stream["received_hex"].replace(
            b"alias-target".hex(), b"wrong-target".hex()
        )
        with self.assertRaisesRegex(ValueError, "data fork"):
            download(report)

    def test_listing_order_is_retained_exactly(self) -> None:
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
        with self.assertRaisesRegex(ValueError, "order/name"):
            listing_views(changed)

    def test_transfer_quiet_observation_is_measured(self) -> None:
        report = self.report("download/file-alias")
        plan = json.loads((BATCH / "download/file-alias/plan.json").read_text())
        event = next(e for e in report["events"] if e["event"] == "quiet")
        event["elapsed_ns"] -= 2_000_000_000
        with self.assertRaisesRegex(ValueError, "missing/short"):
            transfer_quiet(report, plan)

    def test_unknown_description_is_raw_tag(self) -> None:
        report = self.report("info/unknown-tags")
        self.change_field(report, 10, 205, b"Unknown File")
        with self.assertRaisesRegex(ValueError, "bytes"):
            metadata(report, "unknown-tags", b"unknown-tags")

    def test_all_prepared_metadata_kinds_have_distinct_captured_reports(self) -> None:
        self.assertEqual(
            set(information()), {p.name for p in (BATCH / "info").iterdir()}
        )


if __name__ == "__main__":
    unittest.main()
