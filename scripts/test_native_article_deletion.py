"""Reject plausible misreadings of native article deletion and cache evidence."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_news_delete_cases import resume_category, specs
from verify_native_article_deletion import (
    catalogue,
    deletion,
    graph,
    measured_wait,
    scalar_controls,
    verify,
)
from verify_native_auth import reply
from verify_native_shx import fields

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-article-delete-01"
)


class ArticleDeletionTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / name / "report.json").read_text())

    def spec(self, name: str) -> dict:
        return next(s for s in specs() if s["case"] == name)

    def change_field(
        self, report: dict, identifier: int, field: int, value: bytes
    ) -> None:
        next(f for f in reply(report, identifier)["fields"] if f["id"] == field)[
            "hex"
        ] = value.hex()

    def test_entire_paired_corpus_and_physical_caches(self) -> None:
        self.assertEqual(verify(BATCH)["paired_connections"], 60)

    def test_first_child_inherits_deleted_parent_position(self) -> None:
        self.assertEqual(
            graph("promote-parent"),
            (
                [1, 4, 7, 8, 5, 6, 3],
                {
                    1: (0, 4, 0, 0),
                    4: (1, 3, 0, 7),
                    7: (0, 8, 4, 0),
                    8: (7, 5, 4, 0),
                    5: (8, 6, 4, 0),
                    6: (5, 0, 4, 0),
                    3: (4, 0, 0, 0),
                },
            ),
        )

    def test_other_children_do_not_become_root_siblings(self) -> None:
        report = self.report("deletions/parent-one-zero")
        self.change_field(report, 105, 335, bytes(2))
        with self.assertRaisesRegex(ValueError, "body/navigation"):
            deletion(report, self.spec("parent-one-zero"))

    def test_middle_promotion_reparents_second_grandchild(self) -> None:
        report = self.report("deletions/middle-zero")
        self.change_field(report, 108, 335, (2).to_bytes(2, "big"))
        with self.assertRaisesRegex(ValueError, "body/navigation"):
            deletion(report, self.spec("middle-zero"))

    def test_leaf_delete_repairs_first_child_link(self) -> None:
        report = self.report("deletions/leaf-zero")
        self.change_field(report, 104, 336, (7).to_bytes(2, "big"))
        with self.assertRaisesRegex(ValueError, "body/navigation"):
            deletion(report, self.spec("leaf-zero"))

    def test_head_delete_repairs_next_root_previous_link(self) -> None:
        report = self.report("deletions/root-head")
        self.change_field(report, 102, 331, (1).to_bytes(2, "big"))
        with self.assertRaisesRegex(ValueError, "body/navigation"):
            deletion(report, self.spec("root-head"))

    def test_recursive_deletion_removes_descendant_body_access(self) -> None:
        report = self.report("deletions/parent-one-one")
        reply(report, 107)["error"] = 0
        with self.assertRaisesRegex(ValueError, "Deletion error"):
            deletion(report, self.spec("parent-one-one"))

    def test_repeated_delete_is_an_error_not_idempotent_success(self) -> None:
        report = self.report("deletions/repeat-delete")
        reply(report, 12)["error"] = 0
        with self.assertRaisesRegex(ValueError, "Deletion error"):
            deletion(report, self.spec("repeat-delete"))

    def test_zero_mask_can_list_but_cannot_read_bodies(self) -> None:
        report = self.report("deletions/denied")
        reply(report, 101)["error"] = 0
        with self.assertRaisesRegex(ValueError, "Deletion error"):
            deletion(report, self.spec("denied"))

    def test_missing_category_is_not_missing_article_error(self) -> None:
        report = self.report("deletions/missing-category")
        self.change_field(
            report,
            11,
            100,
            b"Cannot delete article because an invalid category or item was specified.",
        )
        with self.assertRaisesRegex(ValueError, "Deletion error"):
            deletion(report, self.spec("missing-category"))

    def test_short_quiet_window_cannot_support_three_seconds(self) -> None:
        report = self.report("deletions/leaf-one")
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            1_000_000_000
        )
        with self.assertRaisesRegex(ValueError, "Short bounded"):
            measured_wait(report, "expect_quiet")

    def test_short_seed_pause_cannot_support_pacing(self) -> None:
        report = self.report("resumed/leaf-one")
        next(e for e in report["events"] if e["event"] == "pause")["elapsed_ns"] -= (
            1_000_000_000
        )
        with self.assertRaisesRegex(ValueError, "Short bounded"):
            measured_wait(report, "pause")

    def test_three_byte_flag_is_not_recursive(self) -> None:
        changed = copy.deepcopy(specs())
        next(s for s in changed if s["case"] == "parent-three-one")["mode"] = (
            "recursive-parent"
        )
        with self.assertRaisesRegex(ValueError, "scalar controls"):
            scalar_controls(changed)

    def test_fifth_flag_byte_is_ignored(self) -> None:
        changed = copy.deepcopy(specs())
        next(s for s in changed if s["case"] == "parent-five-zero")["mode"] = (
            "recursive-parent"
        )
        with self.assertRaisesRegex(ValueError, "scalar controls"):
            scalar_controls(changed)

    def test_seed_cannot_append_to_unowned_or_impossible_prefix(self) -> None:
        for name, count, exists in [
            ("other", 0, False),
            ("leaf-one", 9, True),
            ("leaf-one", 1, False),
        ]:
            with self.subTest(name=name, count=count), self.assertRaises(ValueError):
                resume_category(name, count, exists)

    def test_category_seed_is_bounded_and_paced(self) -> None:
        steps, _ = resume_category("leaf-one")["leaf-one"]
        # Includes login, category creation, eight posts and final listing.
        self.assertEqual(
            sum(
                s["op"] == "send" and not s["hex"].startswith("54525450") for s in steps
            ),
            11,
        )
        self.assertEqual(steps[-2], {"op": "pause", "seconds": 3})

    def test_stored_count_must_match_wire_after_deletion(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in ["native-final", "native-cleanup", "native-published"]:
                shutil.copytree(BATCH / name, target / name)
            rows = json.loads((target / "native-final/extraction.json").read_text())[
                "records"
            ]
            row = next(r for r in rows if r["path"].endswith("/parent-one-one"))
            file = target / "native-final" / (row["key"] + ".data")
            data = file.read_bytes()
            file.write_bytes(data[:44] + (8).to_bytes(4, "big") + data[48:])
            references = {
                s["case"]: fields(reply(self.report("deletions/" + s["case"]), 20))[321]
                for s in specs()
            }
            with self.assertRaisesRegex(ValueError, "storage count/cache"):
                catalogue(target, references)


if __name__ == "__main__":
    unittest.main()
