"""Reject plausible misreadings of native article deletion and cache evidence."""

import copy
import json
import shutil
from pathlib import Path

import pytest
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
    / "evidence/gap-remediation/2026-11-13/native-article-delete-01"
)
PAIRED_CONNECTIONS = 60  # the host and guest connections of the retained corpus
ONE_SECOND_NS = 1_000_000_000  # the shortening that makes a window too short
PAUSE_SECONDS = 3  # the pause that ends a resumed category seed
CATEGORY_SEED_SENDS = 11  # login, category creation, eight posts, final listing
HANDSHAKE_PREFIX_HEX = "54525450"  # the TRTP handshake, which is not counted
COUNT_OFFSET = 44  # the stored article count in the cache header
COUNT_BYTES = 4  # the width of the stored article count
WRONG_COUNT = 8  # a stored count that the wire listing does not match
PROMOTED_PARENT_GRAPH = (
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
)


class ArticleDeletionTests:
    """Reject plausible misreadings of native article deletion and cache evidence."""

    def report(self, name: str) -> dict:
        """Load the report of one retained deletion capture.

        Parameters
        ----------
        name : str
            The capture directory, relative to the batch.

        Returns
        -------
        dict
            The parsed ``report.json`` of the capture.
        """
        return json.loads((BATCH / name / "report.json").read_text())

    def spec(self, name: str) -> dict:
        """Return the specification of one owned case.

        Parameters
        ----------
        name : str
            The case name.

        Returns
        -------
        dict
            The specification of the case, from ``specs``.
        """
        return next(s for s in specs() if s["case"] == name)

    def change_field(
        self, report: dict, identifier: int, field: int, value: bytes
    ) -> None:
        """Replace one field of a reply in a loaded report.

        Parameters
        ----------
        report : dict
            The loaded report, changed in place.
        identifier : int
            The identifier of the reply to change.
        field : int
            The identifier of the field to change.
        value : bytes
            The new field value.
        """
        next(f for f in reply(report, identifier)["fields"] if f["id"] == field)[
            "hex"
        ] = value.hex()

    def test_entire_paired_corpus_and_physical_caches(self) -> None:
        """The whole retained corpus verifies with its paired connections."""
        assert verify(BATCH)["paired_connections"] == PAIRED_CONNECTIONS, (
            "the paired connection count differs"
        )

    def test_first_child_inherits_deleted_parent_position(self) -> None:
        """Deleting a parent promotes its first child into the parent's place."""
        assert graph("promote-parent") == PROMOTED_PARENT_GRAPH, (
            "the promoted-parent traversal differs"
        )

    def test_other_children_do_not_become_root_siblings(self) -> None:
        """The other children stay under the promoted child, not at the root."""
        report = self.report("deletions/parent-one-zero")
        self.change_field(report, 105, 335, bytes(2))
        with pytest.raises(ValueError, match="body/navigation"):
            deletion(report, self.spec("parent-one-zero"))

    def test_middle_promotion_reparents_second_grandchild(self) -> None:
        """A promoted middle node reparents the second grandchild under itself."""
        report = self.report("deletions/middle-zero")
        self.change_field(report, 108, 335, (2).to_bytes(2, "big"))
        with pytest.raises(ValueError, match="body/navigation"):
            deletion(report, self.spec("middle-zero"))

    def test_leaf_delete_repairs_first_child_link(self) -> None:
        """Deleting a leaf repairs the first-child link of its parent."""
        report = self.report("deletions/leaf-zero")
        self.change_field(report, 104, 336, (7).to_bytes(2, "big"))
        with pytest.raises(ValueError, match="body/navigation"):
            deletion(report, self.spec("leaf-zero"))

    def test_head_delete_repairs_next_root_previous_link(self) -> None:
        """Deleting the head repairs the previous link of the next root."""
        report = self.report("deletions/root-head")
        self.change_field(report, 102, 331, (1).to_bytes(2, "big"))
        with pytest.raises(ValueError, match="body/navigation"):
            deletion(report, self.spec("root-head"))

    def test_recursive_deletion_removes_descendant_body_access(self) -> None:
        """A recursive deletion makes the descendant bodies unreadable."""
        report = self.report("deletions/parent-one-one")
        reply(report, 107)["error"] = 0
        with pytest.raises(ValueError, match="Deletion error"):
            deletion(report, self.spec("parent-one-one"))

    def test_repeated_delete_is_an_error_not_idempotent_success(self) -> None:
        """Deleting an article twice is an error, not an idempotent success."""
        report = self.report("deletions/repeat-delete")
        reply(report, 12)["error"] = 0
        with pytest.raises(ValueError, match="Deletion error"):
            deletion(report, self.spec("repeat-delete"))

    def test_zero_mask_can_list_but_cannot_read_bodies(self) -> None:
        """A zero access mask may list the articles but not read their bodies."""
        report = self.report("deletions/denied")
        reply(report, 101)["error"] = 0
        with pytest.raises(ValueError, match="Deletion error"):
            deletion(report, self.spec("denied"))

    def test_missing_category_is_not_missing_article_error(self) -> None:
        """A missing category is reported as such, not as a missing article."""
        report = self.report("deletions/missing-category")
        self.change_field(
            report,
            11,
            100,
            b"Cannot delete article because an invalid category or item was specified.",
        )
        with pytest.raises(ValueError, match="Deletion error"):
            deletion(report, self.spec("missing-category"))

    def test_short_quiet_window_cannot_support_three_seconds(self) -> None:
        """A quiet window shorter than the bounded wait is rejected."""
        report = self.report("deletions/leaf-one")
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            ONE_SECOND_NS
        )
        with pytest.raises(ValueError, match="Short bounded"):
            measured_wait(report, "expect_quiet")

    def test_short_seed_pause_cannot_support_pacing(self) -> None:
        """A seed pause shorter than the bounded wait is rejected."""
        report = self.report("resumed/leaf-one")
        next(e for e in report["events"] if e["event"] == "pause")["elapsed_ns"] -= (
            ONE_SECOND_NS
        )
        with pytest.raises(ValueError, match="Short bounded"):
            measured_wait(report, "pause")

    def test_three_byte_flag_is_not_recursive(self) -> None:
        """A three-byte flag is a promotion, so the recursive mode is rejected."""
        changed = copy.deepcopy(specs())
        next(s for s in changed if s["case"] == "parent-three-one")["mode"] = (
            "recursive-parent"
        )
        with pytest.raises(ValueError, match="scalar controls"):
            scalar_controls(changed)

    def test_fifth_flag_byte_is_ignored(self) -> None:
        """A fifth flag byte is ignored, so the recursive mode is rejected."""
        changed = copy.deepcopy(specs())
        next(s for s in changed if s["case"] == "parent-five-zero")["mode"] = (
            "recursive-parent"
        )
        with pytest.raises(ValueError, match="scalar controls"):
            scalar_controls(changed)

    def test_seed_cannot_append_to_unowned_or_impossible_prefix(self) -> None:
        """A seed cannot append to an unowned or an impossible prefix."""
        for name, count, exists in [
            ("other", 0, False),
            ("leaf-one", 9, True),
            ("leaf-one", 1, False),
        ]:
            with pytest.raises(ValueError, match="Invalid owned category/prefix"):
                resume_category(name, count, exists)

    def test_category_seed_is_bounded_and_paced(self) -> None:
        """A category seed is bounded in its sends and paced by a pause."""
        steps, _ = resume_category("leaf-one")["leaf-one"]
        # Includes login, category creation, eight posts and final listing.
        assert (
            sum(
                s["op"] == "send" and not s["hex"].startswith(HANDSHAKE_PREFIX_HEX)
                for s in steps
            )
            == CATEGORY_SEED_SENDS
        ), "the bounded seed send count differs"
        assert steps[-2] == {
            "op": "pause",
            "seconds": PAUSE_SECONDS,
        }, "the seed pause differs"

    def test_stored_count_must_match_wire_after_deletion(self, tmp_path: Path) -> None:
        """A stored article count that the wire does not match is rejected.

        Parameters
        ----------
        tmp_path : pathlib.Path
            A fresh directory that receives the copied corpus.
        """
        target = tmp_path
        for name in ["native-final", "native-cleanup", "native-published"]:
            shutil.copytree(BATCH / name, target / name)
        rows = json.loads((target / "native-final/extraction.json").read_text())[
            "records"
        ]
        row = next(r for r in rows if r["path"].endswith("/parent-one-one"))
        file = target / "native-final" / (row["key"] + ".data")
        data = file.read_bytes()
        file.write_bytes(
            data[:COUNT_OFFSET]
            + WRONG_COUNT.to_bytes(COUNT_BYTES, "big")
            + data[COUNT_OFFSET + COUNT_BYTES :]
        )
        references = {
            s["case"]: fields(reply(self.report("deletions/" + s["case"]), 20))[321]
            for s in specs()
        }
        with pytest.raises(ValueError, match="storage count/cache"):
            catalogue(target, references)
