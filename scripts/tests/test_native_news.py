"""Reject wrong category versions, tail padding, thread order and cache claims."""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from native_news_decode import METADATA_KIND, articles, categories
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
    / "evidence/gap-remediation/2026-11-13/native-news-01"
)
ROOT_ENTRIES = [
    (b"bundle", True, 2),
    (b"category", False, 6),
    (b"empty", True, 0),
    (b"hi-\x9a", True, 0),
    (b"zero-articles", False, 0),
]
ORDER = [1, 4, 6, 5, 2, 3]
# The counts that the complete native-news corpus must report.
COMPLETED_REPORTS = 43
PAIRED_CONNECTIONS = 45
# The category versions on either side of the numeric branch at fifteen.
LEGACY_VERSION = 14
MODERN_VERSION = 15
# The field of a reply that carries the article list.
ARTICLE_LIST_FIELD = 321
# The navigation field of a body reply.
NAVIGATION_FIELD = 336
# An empty pattern matches every message, which is what assertRaises checked.
ANY_MESSAGE = ""
WORD_BYTES = 4
# The first record's title length: a 10-byte list header and a 22-byte record header.
FIRST_TITLE_LENGTH = 32
# The first record's ID follows the 10-byte list header.
FIRST_ID_START = 10
FIRST_ID_END = 14
ALTERED_ID = 99
# The parent field, counted from the start of its record, which is 23 bytes
# before the title of the second root post.
TITLE_DISTANCE = 23
PARENT_START = 12
PARENT_END = 16
FOREIGN_PARENT = 1
# The list count sits after the 4-byte leading word.
ARTICLE_COUNT_START = 4
ARTICLE_COUNT_END = 8
HIDDEN_COUNT = 5
# The title that is clipped to 31 bytes: "long-" and 26 more bytes.
LONG_TITLE_FILL = 26
# The quiet window that the test shortens, in nanoseconds.
SHORTENED_QUIET_NS = 900_000_000
# A native store file has a 512-byte header, then blocks of a given size.
STORE_HEADER_BYTES = 512
BLOCK_SIZE_START = 32
INDEX_START = 36
ARTICLE_COUNT_AT = 44
INFLATED_COUNT = 5


class NewsTests:  # ruff: ignore[too-many-public-methods]  # pylint: disable=too-many-public-methods  # each test name is a golden key, so the class keeps all twenty
    """Reject wrong category versions, tail padding, thread order and cache claims."""

    def report(self, key: str) -> dict[str, typ.Any]:
        """Load the report of one retained native-news capture.

        Returns
        -------
        dict[str, typing.Any]
            The parsed ``report.json`` of the capture.
        """
        return json.loads((BATCH / key / "report.json").read_text())

    def value(self) -> bytes:
        """Return the article list of the grandchild reply.

        Returns
        -------
        bytes
            The bytes of the article-list field.
        """
        return fields(reply(self.report("grandchild"), 40))[ARTICLE_LIST_FIELD]

    def cache_inputs(
        self,
    ) -> tuple[dict[int, bytes], dict[bytes, dict[str, typ.Any]]]:
        """Rebuild the references and the modern category records of version 15.

        Returns
        -------
        tuple[dict[str, typing.Any], dict[str, typing.Any]]
            The article-list references by reply, and the modern records by name.
        """
        report = self.report("listings/version-15")
        references = {
            i: fields(reply(report, i))[ARTICLE_LIST_FIELD] for i in [20, 21, 22]
        }
        modern: dict[bytes, dict[str, typ.Any]] = {}
        for i in [10, 12, 13]:
            modern.update({
                r["name"]: r
                for r in categories(reply(report, i))
                if r["kind"] == METADATA_KIND
            })
        return references, modern

    def test_complete_native_news_corpus(self) -> None:
        """The complete native-news corpus verifies with its counts and order."""
        result = verify(BATCH)
        assert (result["completed_reports"], result["paired_connections"]) == (
            COMPLETED_REPORTS,
            PAIRED_CONNECTIONS,
        ), "the completed report or paired connection count differs"
        assert result["threaded_public_id_order"] == ORDER, (
            "the threaded public-ID order differs"
        )

    def test_category_branch_changes_at_numeric_fifteen(self) -> None:
        """A category view that takes the wrong version branch is refused."""
        for actual, wrong in [
            (LEGACY_VERSION, MODERN_VERSION),
            (MODERN_VERSION, LEGACY_VERSION),
        ]:
            with pytest.raises(ValueError, match="version branch"):
                category_view(
                    reply(self.report(f"listings/version-{actual}"), 10),
                    wrong,
                    ROOT_ENTRIES,
                )

    def test_nonzero_opaque_tail_is_preserved(self) -> None:
        """The nonzero opaque tail of the first category is kept unchanged."""
        frame = reply(self.report("listings/version-15"), 10)
        row = categories(frame)[0]
        assert row["tail"] == b"\x10", "the opaque tail byte differs"
        assert row["name"] == b"bundle", "the first category name differs"

    def test_folder_record_cannot_drop_the_extra_emitted_byte(self) -> None:
        """A folder record one byte short of its exact length is refused."""
        frame = copy.deepcopy(reply(self.report("listings/version-15"), 10))
        frame["fields"][0]["hex"] = frame["fields"][0]["hex"][:-2]
        with pytest.raises(ValueError, match="exact length"):
            categories(frame)

    def test_article_count_includes_missing_body_metadata(self) -> None:
        """An article count that includes a missing-body record is refused."""
        frame = copy.deepcopy(reply(self.report("listings/version-15"), 10))
        record = frame["fields"][1]
        value = bytes.fromhex(record["hex"])
        record["hex"] = (value[:2] + b"\0\5" + value[4:]).hex()
        with pytest.raises(ValueError, match="count/valence"):
            category_view(frame, 15, ROOT_ENTRIES)

    def test_article_list_count_cannot_hide_a_record(self) -> None:
        """An article-list count that hides a record leaves unconsumed bytes."""
        value = self.value()
        changed = (
            value[:ARTICLE_COUNT_START]
            + HIDDEN_COUNT.to_bytes(WORD_BYTES, "big")
            + value[ARTICLE_COUNT_END:]
        )
        with pytest.raises(ValueError, match="Unconsumed"):
            articles(changed)

    def test_public_id_traversal_is_not_numeric_sort_order(self) -> None:
        """A public ID that breaks the traversal order is refused."""
        value = self.value()
        changed = (
            value[:FIRST_ID_START]
            + ALTERED_ID.to_bytes(WORD_BYTES, "big")
            + value[FIRST_ID_END:]
        )
        with pytest.raises(ValueError, match="order/public IDs"):
            article_records(changed, ORDER)

    def test_parent_field_is_not_previous_sibling(self) -> None:
        """A parent field that names a foreign article is refused."""
        value = self.value()
        start = value.index(b"Second root") - TITLE_DISTANCE
        changed = (
            value[: start + PARENT_START]
            + FOREIGN_PARENT.to_bytes(WORD_BYTES, "big")
            + value[start + PARENT_END :]
        )
        with pytest.raises(ValueError, match="parent/flags"):
            article_records(changed, ORDER)

    def test_flags_word_is_preserved_without_named_bit_guessing(self) -> None:
        """A zeroed flags word is refused rather than read as named bits."""
        value = self.value().replace(bytes.fromhex("11223344"), bytes(4), 1)
        with pytest.raises(ValueError, match="parent/flags"):
            article_records(value, ORDER)

    def test_large_flavour_length_is_unsigned_65535(self) -> None:
        """A flavour length of 65535 is read as an unsigned value and refused."""
        value = self.value().replace(b"text/plain\xff\xff", b"text/plain\0\0", 1)
        with pytest.raises(ValueError, match="cardinality/name/size"):
            article_records(value, ORDER)

    def test_title_is_the_native_posters_clipped_31_byte_value(self) -> None:
        """A changed clipped title is refused against the poster's value."""
        value = self.value().replace(
            b"long-" + b"x" * LONG_TITLE_FILL, b"long-" + b"X" * LONG_TITLE_FILL, 1
        )
        with pytest.raises(ValueError, match="title/poster"):
            article_records(value, ORDER)

    def test_missing_body_error_leaves_a_zero_flavour_article(self) -> None:
        """A missing-body post leaves an article with no flavours."""
        value = fields(reply(self.report("posts"), 43))[ARTICLE_LIST_FIELD]
        rows = article_records(value, [1, 2, 3])
        assert rows[-1]["title"] == b"Missing body", "the last title differs"
        assert rows[-1]["flavours"] == [], "the last article has flavours"

    def test_truncated_pascal_strings_are_rejected(self) -> None:
        """A Pascal string whose length runs past the list is refused."""
        value = self.value()
        # The first title length is at list-header10 + record-header22.
        value = value[:FIRST_TITLE_LENGTH] + b"\xff" + value[FIRST_TITLE_LENGTH + 1 :]
        with pytest.raises(ValueError, match=ANY_MESSAGE):
            articles(value)

    def test_optional_extra_string_is_not_in_the_network_mode(self) -> None:
        """An extra string after the framing fixture is refused."""
        value = self.value()
        offset = value.index(b"framing-fixture") + len(b"framing-fixture")
        changed = value[:offset] + b"\0" + value[offset:]
        with pytest.raises(ValueError, match=ANY_MESSAGE):
            articles(changed)

    def test_body_graph_distinguishes_first_child_from_next_sibling(self) -> None:
        """A body whose navigation link is changed is refused."""
        report = self.report("bodies/root-first")
        next(f for f in reply(report, 10)["fields"] if f["id"] == NAVIGATION_FIELD)[
            "hex"
        ] = "0002"
        by_id = {r["id"]: r for r in articles(self.value())}
        with pytest.raises(ValueError, match="navigation/date graph"):
            body_reply(report, {"case": "root-first", "id": 1}, by_id)

    def test_invalid_flavour_is_not_reported_as_a_successful_empty_body(self) -> None:
        """An unknown flavour with a success error code is still refused."""
        report = self.report("bodies/unknown-flavour")
        reply(report, 10)["error"] = 0
        with pytest.raises(ValueError, match="error family"):
            body_reply(report, {"case": "unknown-flavour", "id": 1}, {})

    def test_protected_root_delete_keeps_its_error_reply(self) -> None:
        """The protected news root keeps its error reply on deletion."""
        report = self.report("structures/delete-protected-news-root")
        reply(report, 11)["error"] = 0
        with pytest.raises(ValueError, match="Structure error"):
            structure(report, {"case": "delete-protected-news-root", "role": "admin"})

    def test_quiet_windows_are_measured(self) -> None:
        """A quiet window that is measured too short is refused."""
        report = self.report("listings/version-15")
        plan = json.loads((BATCH / "listings/version-15/plan.json").read_text())
        next(e for e in report["events"] if e["event"] == "quiet")["elapsed_ns"] -= (
            SHORTENED_QUIET_NS
        )
        with pytest.raises(ValueError, match="short"):
            creation_quiet(report, plan)

    def test_disk_cache_must_equal_the_rebuilt_wire_list(self, tmp_path: Path) -> None:
        """A disk cache that differs from the rebuilt wire list is refused."""
        target = tmp_path
        for name in ["native-final", "native-cleanup", "native-published"]:
            shutil.copytree(BATCH / name, target / name)
        extraction = json.loads((target / "native-final/extraction.json").read_text())
        row = next(r for r in extraction["records"] if r["path"].endswith("/category"))
        path = target / "native-final" / (row["key"] + ".data")
        value = bytearray(path.read_bytes())
        block = int.from_bytes(
            value[BLOCK_SIZE_START : BLOCK_SIZE_START + WORD_BYTES], "big"
        )
        index = int.from_bytes(value[INDEX_START : INDEX_START + WORD_BYTES], "big")
        value[STORE_HEADER_BYTES + (index - 1) * block] = 1
        path.write_bytes(value)
        with pytest.raises(ValueError, match="cached list"):
            catalogue(target, *self.cache_inputs())

    def test_category_count_matches_native_header_not_only_a_decoder(
        self, tmp_path: Path
    ) -> None:
        """The category count must match the native header, not only the decoder."""
        target = tmp_path
        for name in ["native-final", "native-cleanup", "native-published"]:
            shutil.copytree(BATCH / name, target / name)
        extraction = json.loads((target / "native-final/extraction.json").read_text())
        row = next(r for r in extraction["records"] if r["path"].endswith("/category"))
        path = target / "native-final" / (row["key"] + ".data")
        value = path.read_bytes()
        path.write_bytes(
            value[:ARTICLE_COUNT_AT]
            + INFLATED_COUNT.to_bytes(WORD_BYTES, "big")
            + value[ARTICLE_COUNT_AT + WORD_BYTES :]
        )
        with pytest.raises(ValueError, match="HLNZ article count"):
            catalogue(target, *self.cache_inputs())
