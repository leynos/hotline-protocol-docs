"""Tests for the reachability rule (obligation INV-REACH)."""

import typing as typ

import check_links
import check_reach

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder

CONTENTS = "# Contents\n\n- [A](a/one.md)\n- [B](a/two.md)\n- [Top](guide.md)\n"
ROWS = "| [One](one.md) | x |\n| [Two](two.md) | y |\n"
OVERVIEW = "# A\n\n| Document | Use |\n| --- | --- |\n" + ROWS


def tree() -> dict[str, str | bytes]:
    """Build a valid documentation tree.

    Returns
    -------
    dict[str, str | bytes]
        Relative paths to content.
    """
    return {
        "docs/contents.md": CONTENTS,
        "docs/guide.md": "# Guide\n",
        "docs/a/README.md": OVERVIEW,
        "docs/a/one.md": "# One\n",
        "docs/a/two.md": "# Two\n",
        "docs/execplans/plan.md": "# Plan\n",
    }


def test_a_complete_tree_has_no_findings(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Execution plans, overviews and the contents page need no listing."""
    make_tree(tmp_path, tree())
    assert check_reach.check_reach(tmp_path) == [], "unexpected findings"


def test_document_missing_from_contents_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A document the contents page omits is named."""
    make_tree(
        tmp_path,
        {**tree(), "docs/contents.md": CONTENTS.replace("- [B](a/two.md)\n", "")},
    )
    assert check_reach.check_reach(tmp_path) == [
        "docs/a/two.md: is not listed in docs/contents.md"
    ], "missing document"


def test_document_listed_twice_in_contents_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A repeated contents entry is named with its count."""
    make_tree(
        tmp_path, {**tree(), "docs/contents.md": CONTENTS + "- [again](guide.md)\n"}
    )
    assert check_reach.check_reach(tmp_path) == [
        "docs/guide.md: is listed 2 times in docs/contents.md"
    ], "doubly listed"


def test_document_missing_from_its_overview_table_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A set document absent from the overview's table is named."""
    make_tree(
        tmp_path,
        {**tree(), "docs/a/README.md": OVERVIEW.replace("| [Two](two.md) | y |\n", "")},
    )
    assert check_reach.check_reach(tmp_path) == [
        "docs/a/two.md: is not listed in docs/a/README.md"
    ], "missing from overview"


def test_prose_mention_does_not_count_as_a_table_listing(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Only table rows of the overview count; a prose link does not."""
    overview = (
        OVERVIEW.replace("| [Two](two.md) | y |\n", "") + "\nSee [Two](two.md).\n"
    )
    make_tree(tmp_path, {**tree(), "docs/a/README.md": overview})
    assert len(check_reach.check_reach(tmp_path)) == 1, "prose counted as listing"


def test_document_listed_twice_in_overview_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Two table rows for one document are named with their count."""
    make_tree(
        tmp_path, {**tree(), "docs/a/README.md": OVERVIEW + "| [Two](two.md) | z |\n"}
    )
    assert check_reach.check_reach(tmp_path) == [
        "docs/a/two.md: is listed 2 times in docs/a/README.md"
    ], "doubly listed in overview"


def test_set_without_overview_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Documents of a set whose overview is absent are not reachable."""
    files = tree()
    del files["docs/a/README.md"]
    make_tree(tmp_path, files)
    assert len(check_reach.check_reach(tmp_path)) == 2, "both set documents reported"


def test_exempt_working_records_need_no_listing(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A path named in ``exempt`` is skipped."""
    make_tree(tmp_path, {**tree(), "docs/record.md": "# Record\n"})
    assert check_reach.check_reach(tmp_path), "record should be reported"
    found = check_reach.check_reach(tmp_path, exempt=frozenset({"docs/record.md"}))
    assert found == [], "exempt record reported"


def test_link_checker_applies_the_rule_only_when_contents_exists(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """The real run wires the rule in once ``docs/contents.md`` exists."""
    make_tree(tmp_path, {"docs/loose.md": "# Loose\n"})
    assert not check_links.check(tmp_path).failures, "rule applied without contents"
    make_tree(tmp_path, {"docs/contents.md": "# Contents\n"})
    failures = check_links.check(tmp_path).failures
    assert failures == ["docs/loose.md: is not listed in docs/contents.md"], failures


def test_a_link_in_a_later_table_cell_is_a_reference_not_a_listing(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Only the first cell of a row lists a document; other cells may cite it."""
    files = tree()
    files["docs/a/README.md"] = (
        OVERVIEW + "\n| Topic | See |\n| --- | --- |\n| t | [One](one.md) |\n"
    )
    make_tree(tmp_path, files)
    assert check_reach.check_reach(tmp_path) == [], "a citing cell was counted"


def test_a_link_inside_a_contents_description_is_not_a_listing(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """In the contents page only the link that opens a list item lists a document."""
    files = tree()
    files["docs/contents.md"] = CONTENTS.replace(
        "- [B](a/two.md)\n", "- [B](a/two.md): uses the [guide](guide.md).\n"
    )
    make_tree(tmp_path, files)
    assert check_reach.check_reach(tmp_path) == [], "a described link was counted"
