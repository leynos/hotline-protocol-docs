"""Guard native append boundary, indexed orphan and asymmetric link evidence."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_news_boundary_cases import append
from native_news_decode import articles
from verify_native_auth import reply
from verify_native_news_boundary import body, storage, traversal, verify
from verify_native_shx import fields

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-news-boundary-01"
)


class NewsBoundaryTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / name / "report.json").read_text())

    def dates(self) -> dict[int, bytes]:
        # The final successful append bypasses ID102, so retain its earlier date.
        return {
            r["id"]: r["date"]
            for name in ["append-101-101", "append-102-102"]
            for r in articles(fields(reply(self.report(name), 20))[321])
        }

    def final(self) -> bytes:
        return fields(reply(self.report("final"), 10))[321]

    def change_link(self, identifier: int, field: int, value: int) -> dict:
        frame = reply(self.report("observe"), 1000 + identifier)
        next(f for f in frame["fields"] if f["id"] == field)["hex"] = value.to_bytes(
            2, "big"
        ).hex()
        return frame

    def test_complete_paired_and_native_storage_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(
            (result["stored_indexed_articles"], result["reachable_list_articles"]),
            (103, 102),
        )

    def test_101_children_are_still_reachable(self) -> None:
        value = fields(reply(self.report("append-101-101"), 20))[321]
        self.assertEqual([r["id"] for r in articles(value)], list(range(1, 103)))

    def test_102nd_child_bypasses_101st_not_new_child(self) -> None:
        self.assertEqual(
            [r["id"] for r in articles(self.final())], list(range(1, 102)) + [103]
        )

    def test_preboundary_cache_cannot_stand_in_for_postboundary_cache(self) -> None:
        value = fields(reply(self.report("append-101-101"), 20))[321]
        with self.assertRaisesRegex(ValueError, "traversal"):
            traversal(value, 102, self.dates())

    def test_bypassed_article_is_not_deleted_or_unreadable(self) -> None:
        frame = reply(self.report("observe"), 1102)
        frame["error"] = 1
        with self.assertRaisesRegex(ValueError, "direct body"):
            body(frame, 102, self.dates())

    def test_preceding_sibling_points_past_the_indexed_orphan(self) -> None:
        with self.assertRaisesRegex(ValueError, "navigation"):
            body(self.change_link(101, 332, 102), 101, self.dates())

    def test_new_child_previous_link_is_not_preceding_public_id(self) -> None:
        with self.assertRaisesRegex(ValueError, "navigation"):
            body(self.change_link(103, 331, 102), 103, self.dates())

    def test_orphan_retains_its_asymmetric_previous_link(self) -> None:
        with self.assertRaisesRegex(ValueError, "navigation"):
            body(self.change_link(102, 331, 0), 102, self.dates())

    def mutate_storage(self, operation) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in [
                "native-final-positive",
                "native-final",
                "native-final-wide",
                "native-cleanup",
                "native-published",
            ]:
                shutil.copytree(BATCH / name, target / name)
            rows = json.loads(
                (target / "native-final-positive/extraction.json").read_text()
            )["records"]
            row = next(r for r in rows if r["path"].endswith("/siblings"))
            path = target / "native-final-positive" / (row["key"] + ".data")
            data = bytearray(path.read_bytes())
            operation(data)
            path.write_bytes(data)
            storage(target, self.final(), self.dates())

    def test_native_count_must_not_be_normalized_to_reachable_count(self) -> None:
        with self.assertRaisesRegex(ValueError, "stored article count"):
            self.mutate_storage(
                lambda data: data.__setitem__(slice(44, 48), (102).to_bytes(4, "big"))
            )

    def test_orphan_must_remain_in_native_id_index(self) -> None:
        def remove_index(data: bytearray) -> None:
            # Bucket 102&31 is described by the header's index block pointer.
            base = 512 + (int.from_bytes(data[72:76], "big") - 1) * 256
            first = int.from_bytes(data[base + 6 * 8 : base + 6 * 8 + 4], "big")
            start = 512 + (first - 1) * 256
            count = int.from_bytes(data[base + 6 * 8 + 4 : base + 6 * 8 + 8], "big")
            for i in range(count):
                entry = start + i * 8
                if int.from_bytes(data[entry : entry + 4], "big") == 102:
                    data[entry + 4 : entry + 8] = bytes(4)
                    return
            raise AssertionError("Fixture has no indexed orphan")

        with self.assertRaisesRegex(ValueError, "ID index"):
            self.mutate_storage(remove_index)

    def test_generator_refuses_unbounded_or_out_of_range_batches(self) -> None:
        for first, last in [(1, 11), (0, 1), (101, 103), (10, 9)]:
            with self.subTest(first=first, last=last), self.assertRaises(ValueError):
                append(first, last)


if __name__ == "__main__":
    unittest.main()
