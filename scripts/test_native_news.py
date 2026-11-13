"""Reject wrong category versions, tail padding, thread order and cache claims."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_news_decode import articles, categories
from verify_native_auth import reply
from verify_native_mkdir import creation_quiet
from verify_native_news import (
    article_records,
    body_reply,
    catalogue,
    category_view,
    structure,
    verify,
)
from verify_native_shx import fields

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-news-01"
)
ROOT_ENTRIES = [
    (b"bundle", True, 2),
    (b"category", False, 6),
    (b"empty", True, 0),
    (b"hi-\x9a", True, 0),
    (b"zero-articles", False, 0),
]
ORDER = [1, 4, 6, 5, 2, 3]


class NewsTests(unittest.TestCase):
    def report(self, key: str) -> dict:
        return json.loads((BATCH / key / "report.json").read_text())

    def value(self) -> bytes:
        return fields(reply(self.report("grandchild"), 40))[321]

    def cache_inputs(self) -> tuple[dict, dict]:
        report = self.report("listings/version-15")
        references = {i: fields(reply(report, i))[321] for i in [20, 21, 22]}
        modern = {}
        for i in [10, 12, 13]:
            modern.update(
                {r["name"]: r for r in categories(reply(report, i)) if r["kind"] == 3}
            )
        return references, modern

    def test_complete_native_news_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(
            (result["completed_reports"], result["paired_connections"]), (43, 45)
        )
        self.assertEqual(result["threaded_public_id_order"], ORDER)

    def test_category_branch_changes_at_numeric_fifteen(self) -> None:
        for actual, wrong in [(14, 15), (15, 14)]:
            with (
                self.subTest(actual=actual),
                self.assertRaisesRegex(ValueError, "version branch"),
            ):
                category_view(
                    reply(self.report(f"listings/version-{actual}"), 10),
                    wrong,
                    ROOT_ENTRIES,
                )

    def test_nonzero_opaque_tail_is_preserved(self) -> None:
        frame = reply(self.report("listings/version-15"), 10)
        row = categories(frame)[0]
        self.assertEqual(row["tail"], b"\x10")
        self.assertEqual(row["name"], b"bundle")

    def test_folder_record_cannot_drop_the_extra_emitted_byte(self) -> None:
        frame = copy.deepcopy(reply(self.report("listings/version-15"), 10))
        frame["fields"][0]["hex"] = frame["fields"][0]["hex"][:-2]
        with self.assertRaisesRegex(ValueError, "exact length"):
            categories(frame)

    def test_article_count_includes_missing_body_metadata(self) -> None:
        frame = copy.deepcopy(reply(self.report("listings/version-15"), 10))
        record = frame["fields"][1]
        value = bytes.fromhex(record["hex"])
        record["hex"] = (value[:2] + b"\0\5" + value[4:]).hex()
        with self.assertRaisesRegex(ValueError, "count/valence"):
            category_view(frame, 15, ROOT_ENTRIES)

    def test_article_list_count_cannot_hide_a_record(self) -> None:
        value = self.value()
        changed = value[:4] + (5).to_bytes(4, "big") + value[8:]
        with self.assertRaisesRegex(ValueError, "Unconsumed"):
            articles(changed)

    def test_public_id_traversal_is_not_numeric_sort_order(self) -> None:
        value = self.value()
        changed = value[:10] + (99).to_bytes(4, "big") + value[14:]
        with self.assertRaisesRegex(ValueError, "order/public IDs"):
            article_records(changed, ORDER)

    def test_parent_field_is_not_previous_sibling(self) -> None:
        value = self.value()
        start = value.index(b"Second root") - 23
        changed = value[: start + 12] + (1).to_bytes(4, "big") + value[start + 16 :]
        with self.assertRaisesRegex(ValueError, "parent/flags"):
            article_records(changed, ORDER)

    def test_flags_word_is_preserved_without_named_bit_guessing(self) -> None:
        value = self.value().replace(bytes.fromhex("11223344"), bytes(4), 1)
        with self.assertRaisesRegex(ValueError, "parent/flags"):
            article_records(value, ORDER)

    def test_large_flavour_length_is_unsigned_65535(self) -> None:
        value = self.value().replace(b"text/plain\xff\xff", b"text/plain\0\0", 1)
        with self.assertRaisesRegex(ValueError, "cardinality/name/size"):
            article_records(value, ORDER)

    def test_title_is_the_native_posters_clipped_31_byte_value(self) -> None:
        value = self.value().replace(b"long-" + b"x" * 26, b"long-" + b"X" * 26, 1)
        with self.assertRaisesRegex(ValueError, "title/poster"):
            article_records(value, ORDER)

    def test_missing_body_error_leaves_a_zero_flavour_article(self) -> None:
        value = fields(reply(self.report("posts"), 43))[321]
        rows = article_records(value, [1, 2, 3])
        self.assertEqual(rows[-1]["title"], b"Missing body")
        self.assertEqual(rows[-1]["flavours"], [])

    def test_truncated_pascal_strings_are_rejected(self) -> None:
        value = self.value()
        # The first title length is at list-header10 + record-header22.
        value = value[:32] + b"\xff" + value[33:]
        with self.assertRaises(ValueError):
            articles(value)

    def test_optional_extra_string_is_not_in_the_network_mode(self) -> None:
        value = self.value()
        offset = value.index(b"framing-fixture") + len(b"framing-fixture")
        changed = value[:offset] + b"\0" + value[offset:]
        with self.assertRaises(ValueError):
            articles(changed)

    def test_body_graph_distinguishes_first_child_from_next_sibling(self) -> None:
        report = self.report("bodies/root-first")
        next(f for f in reply(report, 10)["fields"] if f["id"] == 336)["hex"] = "0002"
        by_id = {r["id"]: r for r in articles(self.value())}
        with self.assertRaisesRegex(ValueError, "navigation/date graph"):
            body_reply(report, {"case": "root-first", "id": 1}, by_id)

    def test_invalid_flavour_is_not_reported_as_a_successful_empty_body(self) -> None:
        report = self.report("bodies/unknown-flavour")
        reply(report, 10)["error"] = 0
        with self.assertRaisesRegex(ValueError, "error family"):
            body_reply(report, {"case": "unknown-flavour", "id": 1}, {})

    def test_protected_root_delete_keeps_its_error_reply(self) -> None:
        report = self.report("structures/delete-protected-news-root")
        reply(report, 11)["error"] = 0
        with self.assertRaisesRegex(ValueError, "Structure error"):
            structure(report, {"case": "delete-protected-news-root", "role": "admin"})

    def test_quiet_windows_are_measured(self) -> None:
        report = self.report("listings/version-15")
        plan = json.loads((BATCH / "listings/version-15/plan.json").read_text())
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            900_000_000
        )
        with self.assertRaisesRegex(ValueError, "short"):
            creation_quiet(report, plan)

    def test_disk_cache_must_equal_the_rebuilt_wire_list(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ["native-final", "native-cleanup", "native-published"]:
                shutil.copytree(BATCH / name, target / name)
            extraction = json.loads(
                (target / "native-final/extraction.json").read_text()
            )
            row = next(
                r for r in extraction["records"] if r["path"].endswith("/category")
            )
            path = target / "native-final" / (row["key"] + ".data")
            value = bytearray(path.read_bytes())
            block = int.from_bytes(value[32:36], "big")
            index = int.from_bytes(value[36:40], "big")
            value[512 + (index - 1) * block] = 1
            path.write_bytes(value)
            with self.assertRaisesRegex(ValueError, "cached list"):
                catalogue(target, *self.cache_inputs())

    def test_category_count_matches_native_header_not_only_a_decoder(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ["native-final", "native-cleanup", "native-published"]:
                shutil.copytree(BATCH / name, target / name)
            extraction = json.loads(
                (target / "native-final/extraction.json").read_text()
            )
            row = next(
                r for r in extraction["records"] if r["path"].endswith("/category")
            )
            path = target / "native-final" / (row["key"] + ".data")
            value = path.read_bytes()
            path.write_bytes(value[:44] + (5).to_bytes(4, "big") + value[48:])
            with self.assertRaisesRegex(ValueError, "HLNZ article count"):
                catalogue(target, *self.cache_inputs())


if __name__ == "__main__":
    unittest.main()
