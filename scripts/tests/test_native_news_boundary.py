"""Guard native append boundary, indexed orphan and asymmetric link evidence."""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_news_boundary_cases import append
from native_news_decode import articles
from verify_native_auth import reply
from verify_native_news_boundary import body, storage, traversal, verify
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-news-boundary-01"
)
# The field of a reply that carries the article list.
ARTICLE_LIST_FIELD = 321
# The counts that the complete corpus must report.
STORED_ARTICLES = 103
REACHABLE_ARTICLES = 102
# The child numbers around the boundary: the last reachable child before the
# orphan, the orphan that the native list bypasses, and the new child.
PRECEDING_ID = 101
ORPHAN_ID = 102
NEW_CHILD_ID = 103
# The last child in the list that the traversal reaches.
LAST_REACHABLE = 102
# The observed reads are numbered from this identifier.
OBSERVE_BASE = 1000
# The link fields of an observed read.
PREVIOUS_LINK_FIELD = 331
PRECEDING_LINK_FIELD = 332
# An empty pattern matches every message, which is what assertRaises checked.
ANY_MESSAGE = ""
# The message of the fixture check that the index bucket holds the orphan.
MISSING_ORPHAN_MESSAGE = "Fixture has no indexed orphan"
WORD_BYTES = 4
# A native store file has a 512-byte header, then 256-byte blocks of index entries.
STORE_HEADER_BYTES = 512
BLOCK_BYTES = 256
INDEX_POINTER_START = 72
INDEX_POINTER_END = 76
# An index entry is an article ID and a position, eight bytes in all.
INDEX_ENTRY_BYTES = 8
# The orphan's bucket is its ID modulo 32, which is 6 for ID 102.
ORPHAN_BUCKET = 6
# The stored article count sits at bytes 44 to 47 of the category file.
STORED_COUNT_START = 44
STORED_COUNT_END = 48
REACHABLE_COUNT = 102


class NewsBoundaryTests:
    """Guard native append boundary, indexed orphan and asymmetric link evidence."""

    def report(self, name: str) -> dict[str, typ.Any]:
        """Load the report of one retained boundary capture.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the capture.
        """
        return json.loads((BATCH / name / "report.json").read_text())

    def dates(self) -> dict[int, bytes]:
        """Map each boundary article to its date, keeping the earlier one.

        Returns
        -------
        dict[int, bytes]
            The eight-byte date of each article, by its ID.
        """
        # The final successful append bypasses ID102, so retain its earlier date.
        return {
            r["id"]: r["date"]
            for name in ["append-101-101", "append-102-102"]
            for r in articles(fields(reply(self.report(name), 20))[ARTICLE_LIST_FIELD])
        }

    def final(self) -> bytes:
        """Return the article list of the final listing.

        Returns
        -------
        bytes
            The bytes of the article-list field.
        """
        return fields(reply(self.report("final"), 10))[ARTICLE_LIST_FIELD]

    def change_link(
        self, identifier: int, field: int, value: int
    ) -> dict[str, typ.Any]:
        """Return an observed read with one link field replaced by ``value``.

        Returns
        -------
        dict[str, typing.Any]
            The changed reply frame.
        """
        frame = reply(self.report("observe"), OBSERVE_BASE + identifier)
        next(f for f in frame["fields"] if f["id"] == field)["hex"] = value.to_bytes(
            2, "big"
        ).hex()
        return frame

    def test_complete_paired_and_native_storage_corpus(self) -> None:
        """The complete boundary corpus verifies its stored and reachable counts."""
        result = verify(BATCH)
        assert (
            result["stored_indexed_articles"],
            result["reachable_list_articles"],
        ) == (STORED_ARTICLES, REACHABLE_ARTICLES), "the article counts differ"

    def test_101_children_are_still_reachable(self) -> None:
        """Every child up to 101 is still reachable in the list."""
        value = fields(reply(self.report("append-101-101"), 20))[ARTICLE_LIST_FIELD]
        assert [r["id"] for r in articles(value)] == list(
            range(1, LAST_REACHABLE + 1)
        ), "the reachable IDs before the boundary differ"

    def test_102nd_child_bypasses_101st_not_new_child(self) -> None:
        """The 102nd child is bypassed, and the new child is reachable instead."""
        assert [r["id"] for r in articles(self.final())] == [
            *range(1, ORPHAN_ID),
            NEW_CHILD_ID,
        ], "the bypass order differs"

    def test_preboundary_cache_cannot_stand_in_for_postboundary_cache(self) -> None:
        """A cache from before the boundary cannot stand in for one after it."""
        value = fields(reply(self.report("append-101-101"), 20))[ARTICLE_LIST_FIELD]
        with pytest.raises(ValueError, match="traversal"):
            traversal(value, ORPHAN_ID, self.dates())

    def test_bypassed_article_is_not_deleted_or_unreadable(self) -> None:
        """The bypassed article remains readable, so an error reply is refused."""
        frame = reply(self.report("observe"), OBSERVE_BASE + ORPHAN_ID)
        frame["error"] = 1
        with pytest.raises(ValueError, match="direct body"):
            body(frame, ORPHAN_ID, self.dates())

    def test_preceding_sibling_points_past_the_indexed_orphan(self) -> None:
        """A preceding sibling that points past the indexed orphan is refused."""
        with pytest.raises(ValueError, match="navigation"):
            body(
                self.change_link(PRECEDING_ID, PRECEDING_LINK_FIELD, ORPHAN_ID),
                PRECEDING_ID,
                self.dates(),
            )

    def test_new_child_previous_link_is_not_preceding_public_id(self) -> None:
        """The new child's previous link is not the preceding public ID."""
        with pytest.raises(ValueError, match="navigation"):
            body(
                self.change_link(NEW_CHILD_ID, PREVIOUS_LINK_FIELD, ORPHAN_ID),
                NEW_CHILD_ID,
                self.dates(),
            )

    def test_orphan_retains_its_asymmetric_previous_link(self) -> None:
        """The orphan keeps its asymmetric previous link, so a zeroed one is refused."""
        with pytest.raises(ValueError, match="navigation"):
            body(
                self.change_link(ORPHAN_ID, PREVIOUS_LINK_FIELD, 0),
                ORPHAN_ID,
                self.dates(),
            )

    def mutate_storage(
        self, tmp_path: Path, operation: cabc.Callable[[bytearray], None]
    ) -> None:
        """Copy the storage captures, apply ``operation`` and verify the result.

        Parameters
        ----------
        tmp_path : pathlib.Path
            The directory that receives the copied captures.
        operation : collections.abc.Callable[[bytearray], None]
            The change to the stored category file.
        """
        target = tmp_path
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

    def test_native_count_must_not_be_normalized_to_reachable_count(
        self, tmp_path: Path
    ) -> None:
        """The stored count is not replaced by the reachable count."""

        def set_stored_count(data: bytearray) -> None:
            """Write the reachable count where the stored count belongs."""
            data[STORED_COUNT_START:STORED_COUNT_END] = REACHABLE_COUNT.to_bytes(
                WORD_BYTES, "big"
            )

        with pytest.raises(ValueError, match="stored article count"):
            self.mutate_storage(tmp_path, set_stored_count)

    def test_orphan_must_remain_in_native_id_index(self, tmp_path: Path) -> None:
        """The orphan must remain in the native ID index."""

        def remove_index(data: bytearray) -> None:
            """Zero the position of the orphan's entry in its index bucket.

            Raises
            ------
            AssertionError
                If the index bucket holds no entry for the orphan.
            """
            # Bucket 102&31 is described by the header's index block pointer.
            base = (
                STORE_HEADER_BYTES
                + (
                    int.from_bytes(data[INDEX_POINTER_START:INDEX_POINTER_END], "big")
                    - 1
                )
                * BLOCK_BYTES
            )
            bucket = base + ORPHAN_BUCKET * INDEX_ENTRY_BYTES
            first = int.from_bytes(data[bucket : bucket + WORD_BYTES], "big")
            start = STORE_HEADER_BYTES + (first - 1) * BLOCK_BYTES
            count = int.from_bytes(
                data[bucket + WORD_BYTES : bucket + INDEX_ENTRY_BYTES], "big"
            )
            for i in range(count):
                entry = start + i * INDEX_ENTRY_BYTES
                if int.from_bytes(data[entry : entry + WORD_BYTES], "big") == ORPHAN_ID:
                    data[entry + WORD_BYTES : entry + INDEX_ENTRY_BYTES] = bytes(
                        WORD_BYTES
                    )
                    return
            raise AssertionError(MISSING_ORPHAN_MESSAGE)

        with pytest.raises(ValueError, match="ID index"):
            self.mutate_storage(tmp_path, remove_index)

    def test_generator_refuses_unbounded_or_out_of_range_batches(self) -> None:
        """The append generator refuses ranges that are unbounded or out of range."""
        for first, last in [(1, 11), (0, 1), (101, 103), (10, 9)]:
            with pytest.raises(ValueError, match=ANY_MESSAGE):
                append(first, last)
