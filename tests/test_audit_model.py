"""Tests for the pure part of the audit refresh: mapping and comparison."""

import copy
import typing as typ

import audit_model as am
import markdown_model as mm
import pytest
import section_map as sm
from hypothesis import given
from hypothesis import strategies as st

if typ.TYPE_CHECKING:
    from pathlib import Path

OLD_TEXT = "# One\n\ntext\n\n## Two\n\nmore\n\n## Three\n"
OLD = mm.section_inventory(OLD_TEXT)


def test_unchanged_headings_map_by_ordinal() -> None:
    """With the same anchors the n-th old section is the n-th new section."""
    new = mm.section_inventory("# One\n\nextra line\n\ntext\n\n## Two\n\n## Three\n")
    mapping = am.build_mapping({"a.md": OLD}, {"a.md": new}, sm.SectionMap({}, {}))
    assert mapping == {("a.md", i): ("a.md", i) for i in (1, 2, 3)}, "ordinal map"


def test_case_only_heading_change_is_allowed() -> None:
    """The slug is lowercased, so a case-only edit keeps the correspondence."""
    new = mm.section_inventory("# ONE\n\n## two\n\n## Three\n")
    mapping = am.build_mapping({"a.md": OLD}, {"a.md": new}, sm.SectionMap({}, {}))
    assert len(mapping) == 3, "case change broke the mapping"


@pytest.mark.parametrize(
    "text",
    [
        "# One\n\n## Two\n",
        "# One\n\n## Two\n\n## New\n\n## Three\n",
        "# One\n\n## Three\n\n## Two\n",
        "# One\n\n## Zwei\n\n## Three\n",
    ],
    ids=["removed", "inserted", "reordered", "renamed"],
)
def test_changed_heading_sequence_is_refused_without_a_map(text: str) -> None:
    """Any added, removed, reordered or renamed heading is refused, by name."""
    new = {"a.md": mm.section_inventory(text)}
    with pytest.raises(sm.RefreshRefusedError, match=r"a\.md"):
        am.build_mapping({"a.md": OLD}, new, sm.SectionMap({}, {}))


def test_relocated_file_maps_through_the_file_map() -> None:
    """A moved document maps by ordinal to its new path."""
    smap = sm.SectionMap({"a.md": "docs/a.md"}, {})
    mapping = am.build_mapping({"a.md": OLD}, {"docs/a.md": OLD}, smap)
    assert mapping["a.md", 2] == ("docs/a.md", 2), "relocation"


def test_explicit_entries_allow_many_to_one() -> None:
    """A restructured document needs every section mapped, many to one allowed."""
    new = {"c.md": mm.section_inventory("# Merged\n\n## Kept\n")}
    entries = {
        ("a.md", 1): ("c.md", 1),
        ("a.md", 2): ("c.md", 1),
        ("a.md", 3): ("c.md", 2),
    }
    mapping = am.build_mapping({"a.md": OLD}, new, sm.SectionMap({}, entries))
    assert mapping == entries, "explicit mapping"


def test_restructured_document_with_an_unmapped_section_is_refused() -> None:
    """Mapping some sections explicitly obliges the map to cover them all."""
    new = {"c.md": mm.section_inventory("# Merged\n\n## Kept\n")}
    entries = {("a.md", 1): ("c.md", 1), ("a.md", 3): ("c.md", 2)}
    with pytest.raises(sm.RefreshRefusedError, match=r"a\.md.*2"):
        am.build_mapping({"a.md": OLD}, new, sm.SectionMap({}, entries))


def test_new_section_without_an_old_counterpart_is_refused() -> None:
    """A section nothing maps to would be uncovered, so the map is refused."""
    new = {"a.md": OLD, "extra.md": mm.section_inventory("# Fresh\n")}
    with pytest.raises(sm.RefreshRefusedError, match=r"extra\.md"):
        am.build_mapping({"a.md": OLD}, new, sm.SectionMap({}, {}))


def test_section_map_loading_validates_its_shape(tmp_path: Path) -> None:
    """The map file holds ``files`` and ``sections`` with one-based ordinals."""
    path = tmp_path / "map.json"
    path.write_text(
        '{"files": {"a.md": "b.md"},'
        ' "sections": [{"old": ["x.md", 1], "new": ["y.md", 2]}]}'
    )
    loaded = sm.load_section_map(path)
    assert loaded == sm.SectionMap({"a.md": "b.md"}, {("x.md", 1): ("y.md", 2)}), "load"
    path.write_text('{"sections": [{"old": ["x.md", 0], "new": ["y.md", 1]}]}')
    with pytest.raises(sm.RefreshRefusedError, match="ordinal"):
        sm.load_section_map(path)


def test_compare_reports_each_protected_change_and_ignores_the_rest() -> None:
    """A changed protected field is named; a changed source is not a change."""
    old = {
        "gaps": [
            {"id": "GAP-001", "closure_criteria": "a", "status": "Open", "sources": [1]}
        ]
    }
    new = copy.deepcopy(old)
    new["gaps"][0]["sources"] = [2]
    assert am.compare_registers(old, new) == [], "sources are not protected"
    new["gaps"][0]["closure_criteria"] = "b"
    found = am.compare_registers(old, new)
    assert len(found) == 1, found
    assert "GAP-001" in found[0], found[0]
    assert "closure_criteria" in found[0], found[0]


def test_compare_detects_added_and_removed_gaps() -> None:
    """The gap identifiers themselves are protected."""
    old = {"gaps": [{"id": "GAP-001"}, {"id": "GAP-002"}]}
    new = {"gaps": [{"id": "GAP-001"}]}
    assert any("GAP-002" in found for found in am.compare_registers(old, new)), (
        "removed"
    )


@given(
    inserts=st.lists(
        st.tuples(st.integers(0, 40), st.text("abc ", max_size=8)), max_size=6
    )
)
def test_inserting_prose_never_moves_anchors(inserts: list[tuple[int, str]]) -> None:
    """Inserting non-heading lines changes line numbers but not the mapping."""
    lines: list[str] = []
    lines.extend(OLD_TEXT.splitlines())
    for position, text in inserts:
        lines.insert(position % (len(lines) + 1), "x" + text.replace("#", ""))
    new = mm.section_inventory("\n".join(lines) + "\n")
    mapping = am.build_mapping({"a.md": OLD}, {"a.md": new}, sm.SectionMap({}, {}))
    assert mapping == {("a.md", i): ("a.md", i) for i in (1, 2, 3)}, "anchors moved"
    assert [s["anchor"] for s in new] == [s["anchor"] for s in OLD], "anchor sequence"
