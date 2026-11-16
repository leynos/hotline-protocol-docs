"""Tests for the status rule of ``check_evidence`` (obligation INV-STATUS)."""

import typing as typ

import check_evidence
import pytest
from evidence_helpers import DOC_PATH, NOTE, build, doc_with

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder


@pytest.mark.parametrize(
    "sentence",
    [
        "GAP-001 remains open.",
        "GAP-001 stays Investigating for now.",
        "The GAP-001 criterion is still open.",
        "[GAP-001](../../gap-analysis.md#gap-001) is not resolved.",
        "GAP-001's evidence remains unresolved.",
        "Unexplained deltas leave GAP-001 open.",
        "GAP-002 is resolved.",
        "GAP-003 was closed.",
        "GAP-002 remains Open.",
        "GAP-003 remains Investigating.",
        "- GAP-001 remains open.",
        "| GAP-001 remains open |",
    ],
)
def test_contradicting_status_sentence_is_reported(
    tmp_path: Path, make_tree: TreeBuilder, sentence: str
) -> None:
    """A sentence that asserts a status the register does not hold is found."""
    root = build(tmp_path, make_tree, doc_with(sentence))
    (finding,) = check_evidence.run_check(root).findings
    assert finding.rule == "status", "rule"
    assert finding.path == DOC_PATH, "path"


@pytest.mark.parametrize(
    "sentence",
    [
        "GAP-002 remains open.",
        "GAP-001 is Resolved.",
        "GAP-003 remains Open.",
        "GAP-002 stays Investigating.",
        "Supplied-text encoding remains GAP-001.",
        "This packet does not close GAP-001.",
        "The evidence remains open; GAP-001 is Resolved.",
        "GAP-001 is Resolved, while GAP-002 remains open.",
        "Unreconciled: GAP-001 remains open here and is Resolved there.",
        "> Status note (2026-11-16): GAP-001 remains open no longer; it is Resolved.",
    ],
)
def test_consistent_or_exempt_sentence_is_accepted(
    tmp_path: Path, make_tree: TreeBuilder, sentence: str
) -> None:
    """Consistent claims, clause boundaries, notes and Unreconciled paragraphs pass."""
    root = build(tmp_path, make_tree, doc_with(sentence))
    assert not check_evidence.run_check(root).findings, "unexpected findings"


def test_status_cell_is_compared_with_the_register(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A table's Status column must agree with the register."""
    rows = ["| Gap | Status |", "| --- | --- |", "| GAP-001 | Open |"]
    table = "\n".join([*rows, "| GAP-002 | Investigating |"])
    root = build(tmp_path, make_tree, doc_with(table))
    (finding,) = check_evidence.run_check(root).findings
    assert finding.message == "GAP-001 is Open here but Resolved in the register", (
        "message"
    )
    assert finding.line == 7, "line"


def test_a_dated_note_in_the_same_section_accepts_the_sentence(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """The same sentence passes when a valid note for the gap follows it."""
    root = build(tmp_path, make_tree, doc_with("GAP-001 remains open.", NOTE.strip()))
    result = check_evidence.run_check(root)
    assert not result.findings, "unexpected findings"
    unannotated = build(tmp_path / "bare", make_tree, doc_with("GAP-001 remains open."))
    assert len(check_evidence.run_check(unannotated).findings) == 1, "the control"


@pytest.mark.parametrize(
    ("note", "rule"),
    [
        (
            "> Status note (2026-11-16): the register lists GAP-002 as Resolved.",
            "status",
        ),
        ("> Status note (2026-11-16): GAP-001 has been revisited.", "status"),
        ("> Status note (16 November 2026): GAP-001 is Resolved.", "status-note"),
        ("> Status note (2026-13-45): GAP-001 is Resolved.", "status-note"),
        ("> A note: GAP-001 is Resolved.", "status"),
    ],
)
def test_invalid_notes_do_not_accept_the_sentence(
    tmp_path: Path, make_tree: TreeBuilder, note: str, rule: str
) -> None:
    """A note for another gap, without the status, or undated does not count."""
    root = build(tmp_path, make_tree, doc_with("GAP-001 remains open.", note))
    assert rule in {f.rule for f in check_evidence.run_check(root).findings}, "rule"


@pytest.mark.parametrize(
    "paragraphs",
    [
        ("GAP-001 remains open.", f"## Elsewhere\n\n{NOTE.strip()}"),
        (NOTE.strip(), "GAP-001 remains open."),
    ],
)
def test_a_note_must_follow_in_the_same_section(
    tmp_path: Path, make_tree: TreeBuilder, paragraphs: tuple[str, ...]
) -> None:
    """A note in another section, or before the sentence, does not count."""
    root = build(tmp_path, make_tree, doc_with(*paragraphs))
    assert [f.rule for f in check_evidence.run_check(root).findings] == ["status"], (
        "rules"
    )
