"""Tests for the shared Markdown model: headings, anchors and links."""

import json
from pathlib import Path

import markdown_model as mm
import pytest
from hypothesis import given
from hypothesis import strategies as st

REVISION = Path("evidence/protocol-gap-analysis/2026-11-15/revision-89")
EXPECTED_SECTIONS = 543


def test_anchor_rule_reproduces_every_recorded_revision_89_inventory(
    mothra: Path,
) -> None:
    """The slug rule equals the renderer's on all 543 recorded anchors."""
    manifest = json.loads((mothra / REVISION / "manifest.json").read_text())
    recorded = json.loads((mothra / REVISION / "sections.json").read_text())
    total = 0
    for item in manifest["inputs"]:
        snapshot = mothra / item["snapshot"].removeprefix("../mothra/")
        found = mm.section_inventory(snapshot.read_text())
        assert found == recorded[item["path"]], f"inventory differs: {item['path']}"
        total += len(found)
    assert total == EXPECTED_SECTIONS, f"expected 543 sections, found {total}"


@pytest.mark.parametrize(
    ("title", "anchor"),
    [
        ("Plain Title", "plain-title"),
        (
            "Hotline 1.9: Transactions & Functionality",
            "hotline-19-transactions--functionality",
        ),
        ("Under_score and-hyphen", "under_score-and-hyphen"),
        ("`code` span", "code-span"),
        ("Ünïcode Ünder", "ünïcode-ünder"),
    ],
)
def test_slug_rule(title: str, anchor: str) -> None:
    """The slug lowercases, drops other punctuation and hyphenates spaces."""
    assert mm.slug(title) == anchor, f"slug({title!r}) != {anchor!r}"


@given(st.text())
def test_slug_is_idempotent(title: str) -> None:
    """Slugging a slug changes nothing, and a slug holds no space or capital."""
    once = mm.slug(title)
    assert mm.slug(once) == once, "slug is not a fixed point"
    assert " " not in once, "slug still holds a space"


def test_inventory_ignores_fenced_headings_and_records_ranges() -> None:
    """Headings inside fences are not sections; ranges end before the next."""
    text = "# One\n\n```\n# not a heading\n```\n## Two\n~~~\n## nor this\n~~~\ntext\n"
    found = mm.section_inventory(text)
    assert [s["heading"] for s in found] == ["One", "Two"], "wrong headings"
    assert (found[0]["line_start"], found[0]["line_end"]) == (1, 5), "range one"
    assert (found[1]["line_start"], found[1]["line_end"]) == (6, 10), "range two"


@pytest.mark.parametrize(
    ("text", "targets"),
    [
        ("see [a](x.md) and [b](y.md#z)", ["x.md", "y.md#z"]),
        ("[ref]: other.md#top", ["other.md#top"]),
        ('[a](x.md "title")', ["x.md"]),
        ("[a](<x.md>)", ["x.md"]),
        ("[a]( spaced.md)", ["spaced.md"]),
        ("```\n[a](fenced.md)\n```\n[b](live.md)", ["live.md"]),
        ("`[a](code.md)` and [b](live.md)", ["live.md"]),
        ("[a](https://example.com/x)", ["https://example.com/x"]),
    ],
)
def test_link_extraction(text: str, targets: list[str]) -> None:
    """Inline links and reference definitions are found; fences are skipped."""
    assert [link.target for link in mm.extract_links(text)] == targets, "targets"


def test_link_extraction_reports_line_numbers() -> None:
    """Each link carries the one-based line on which it appears."""
    links = mm.extract_links("a\n\n[x](one.md)\n")
    assert [link.line for link in links] == [3], "line number"


def test_explicit_anchors_cover_id_and_name_attributes() -> None:
    """``<a id>`` and ``<a name>`` define anchors; fenced ones do not."""
    text = '<a id="one"></a> <a name="two"></a>\n```\n<a id="three"></a>\n```\n'
    assert mm.explicit_anchors(text) == {"one", "two"}, "explicit anchors"


@pytest.mark.parametrize(
    ("source", "path", "expected"),
    [
        ("a.md", "b.md", (0, ("b.md",))),
        ("d/a.md", "../b.md", (0, ("b.md",))),
        ("d/a.md", "./x/../y.md", (0, ("d", "y.md"))),
        ("a.md", "../mothra/x.md", (1, ("mothra", "x.md"))),
        ("d/a.md", "../../mothra/x.md", (1, ("mothra", "x.md"))),
        ("a.md", "../../up.md", (2, ("up.md",))),
    ],
)
def test_lexical_target(
    source: str, path: str, expected: tuple[int, tuple[str, ...]]
) -> None:
    """Targets are resolved without the file system, counting escapes."""
    assert mm.lexical_target(Path(source), path) == expected, "resolution"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("```python\nx\n```\n", [(1, 3, "python")]),
        ("```\nx\n```\n", [(1, 3, "")]),
        ("~~~ text \nx\n~~~\n", [(1, 3, "text")]),
        ("~~~mermaid\n```\n~~~\n", [(1, 3, "mermaid")]),
        ("```sh\nopen\n", [(1, 2, "sh")]),
        ("prose\n", []),
    ],
)
def test_fences_report_span_and_label(
    text: str, expected: list[tuple[int, int, str]]
) -> None:
    """Each fenced block gives its opening line, closing line and label."""
    found = [(f.start, f.end, f.info) for f in mm.fences(text)]
    assert found == expected, "fences"


def test_table_spans_find_runs_of_pipe_lines_outside_fences() -> None:
    """A table is a run of pipe lines; one inside a fence is not a table."""
    text = "| a |\n| - |\n| 1 |\n\n```\n| no |\n```\n\n| b |\n| - |\n"
    assert mm.table_spans(text) == [(1, 3), (9, 10)], "table spans"
