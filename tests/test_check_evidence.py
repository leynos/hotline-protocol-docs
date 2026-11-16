"""Tests for the evidence check (obligations INV-EVID, INV-STATUS, INV-RECREATE)."""

import json
import typing as typ
from pathlib import Path

import check_evidence
import evidence_cites
import evidence_index
import pytest
from evidence_families import FamilyTable
from evidence_helpers import (
    CORPUS,
    DOC,
    DOC_PATH,
    OTHER,
    base_tree,
    build,
    doc_with,
    rules,
)
from hypothesis import given
from hypothesis import strategies as st
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from tree_helpers import TreeBuilder

REPO = Path(__file__).resolve().parents[1]


def test_a_clean_tree_has_no_findings(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """The synthetic tree is clean and the counts show that it was read."""
    result = check_evidence.run_check(build(tmp_path, make_tree))
    assert not result.findings, "unexpected findings"
    assert result.counts["ledger citations"] == 1, "ledger citations"
    assert result.counts["evidence links"] == 1, "evidence links"
    assert result.corpora["alpha"] == 1, "corpora indexed"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("The entry V099 holds.", [("ledger-id", "V099")]),
        ("The entry M002 holds.", [("ledger-id", "M002")]),
        ("GAP-099 is open.", [("gap-id", "GAP-099")]),
        ("See GAP-001/098 for both.", [("gap-id", "GAP-098")]),
        ("Run `scripts/missing.py` now.", [("script", "scripts/missing.py")]),
        ("Run [it](../../scripts/missing.py).", [("script", "scripts/missing.py")]),
        ("```\npython3 scripts/missing.py\n```", [("script", "scripts/missing.py")]),
        ("Run `scripts/tool.py` and V001.", []),
        ("The scripts/missing.py file, in prose.", []),
        ("A path `evidence/x/scripts/missing.py` is evidence.", []),
    ],
)
def test_identifier_and_script_rules(
    tmp_path: Path, make_tree: TreeBuilder, text: str, expected: list[tuple[str, str]]
) -> None:
    """Each undefined identifier or missing script is reported once."""
    root = build(tmp_path, make_tree, doc_with(text))
    assert rules(check_evidence.run_check(root)) == expected, "findings"


def test_findings_carry_file_and_line(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """A finding renders as ``file:line: rule: message``."""
    root = build(tmp_path, make_tree, doc_with("First line.\n\nThe entry V099 holds."))
    (finding,) = check_evidence.run_check(root).findings
    expected = f"{DOC_PATH}:7: ledger-id: V099 is not defined in claims.json"
    assert finding.render() == expected, "rendering"


@pytest.mark.parametrize(
    ("rows", "expected"),
    [
        ("| GAP-002 |\n| GAP-003 |", []),
        ("| GAP-002 |", [("ledger-table", "GAP-003")]),
        ("| GAP-002 |\n| GAP-003 |\n| GAP-002 |", [("ledger-table", "GAP-002")]),
        ("| GAP-002 |\n| GAP-003 |\n| GAP-001 |", [("ledger-table", "GAP-001")]),
        ("| GAP-002 |\n| GAP-003 |\n| GAP-099 |", [("ledger-table", "GAP-099")]),
    ],
)
def test_ledger_table_lists_each_unresolved_gap_once(
    tmp_path: Path,
    make_tree: TreeBuilder,
    rows: str,
    expected: list[tuple[str, str]],
) -> None:
    """Unresolved gaps appear once, and Resolved or unknown gaps not at all."""
    ledger = f"# Ledger\n\n| Gap |\n| --- |\n{rows}\n\n_Table 1: Gaps._\n"
    root = build(
        tmp_path, make_tree, {"docs/provenance/remaining-evidence-work.md": ledger}
    )
    found = [r for r in rules(check_evidence.run_check(root)) if r[0] == "ledger-table"]
    assert found == expected, "ledger findings"


def test_a_corpus_outside_every_family_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A cited corpus that the guide's table does not cover is named."""
    stray = "evidence/gap-remediation/2026-11-14/stray-corpus-01"
    root = build(
        tmp_path,
        make_tree,
        {**doc_with(f"See `{stray}/manifest.json`."), f"{stray}/manifest.json": "{}"},
    )
    assert rules(check_evidence.run_check(root)) == [("family", stray)], "findings"


def test_the_guide_may_not_name_a_missing_script(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A script named in the guide's code spans must exist."""
    guide = base_tree()["docs/native-evidence/recreating-evidence.md"]
    assert isinstance(guide, str), "the guide is text"
    changed = guide + "\nRun `ghost.py` and `tools/ghost.py` and `tool.py`.\n"
    root = build(
        tmp_path, make_tree, {"docs/native-evidence/recreating-evidence.md": changed}
    )
    keys = [k for r, k in rules(check_evidence.run_check(root)) if r == "guide-script"]
    assert keys == ["ghost.py", "tools/ghost.py"], "guide scripts"


def test_a_stale_or_absent_index_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Regenerating an index must give the bytes on disk."""
    root = build(tmp_path, make_tree, after={"docs/alpha/evidence.md": "# Old\n"})
    assert rules(check_evidence.run_check(root)) == [
        ("index", "docs/alpha/evidence.md")
    ], "stale"
    (root / "docs/alpha/evidence.md").unlink()
    assert "is absent" in check_evidence.run_check(root).findings[0].message, "absent"
    assert check_evidence.main(["index", "--root", str(root)]) == EXIT_FINDINGS, "stale"
    assert check_evidence.main(["index", "--root", str(root), "--write"]) == EXIT_OK, (
        "write"
    )
    assert check_evidence.main(["index", "--root", str(root)]) == EXIT_OK, "current"
    assert not check_evidence.write_indexes(root), "second write changes nothing"


@pytest.mark.parametrize(
    "needle",
    [
        f"[`{CORPUS}`](../../{CORPUS}/manifest.json)",
        "F2 Static query batches",
        "[`doc.md`, Section one](doc.md#section-one)",
        "[V001](../baseline-validity-ledger.md)",
        "[GAP-002](../../gap-analysis.md#gap-002)",
        "# Evidence index\n\nThis file is generated by",
        "_Table 1: Corpora cited by the `alpha` documents._",
    ],
)
def test_the_index_links_each_corpus_and_citing_section(
    tmp_path: Path, make_tree: TreeBuilder, needle: str
) -> None:
    """The index gives corpus, family, citing section, ledger and gap rows."""
    root = build(tmp_path, make_tree)
    text = (root / "docs/alpha/evidence.md").read_text(encoding="utf-8")
    assert needle in text, needle


def test_known_findings_are_accepted_and_stale_entries_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """An accepted finding is moved aside; an entry that matches none is a finding."""
    root = build(tmp_path, make_tree, doc_with("The entry V099 holds."))
    entry = {"rule": "ledger-id", "path": DOC_PATH, "key": "V099", "reason": "test"}
    stale = {"rule": "gap-id", "path": DOC_PATH, "key": "GAP-099", "reason": "test"}
    (root / "known.json").write_text(json.dumps([entry]), encoding="utf-8")
    options = check_evidence.Options(known=Path("known.json"))
    result = check_evidence.run_check(root, options)
    assert (result.findings, len(result.accepted)) == ([], 1), "accepted"
    (root / "known.json").write_text(json.dumps([entry, stale]), encoding="utf-8")
    result = check_evidence.run_check(root, options)
    assert [f.rule for f in result.findings] == ["known"], "stale entry"


def test_non_vacuity_floors_fail_a_run_that_saw_too_little(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A run below the floors fails, so an empty run cannot pass."""
    root = build(tmp_path, make_tree)
    options = check_evidence.Options(min_ledger=5, min_links=5)
    keys = [
        k for r, k in rules(check_evidence.run_check(root, options)) if r == "floor"
    ]
    assert sorted(keys) == ["evidence links", "ledger citations"], "floors"


def test_missing_register_is_a_missing_input(tmp_path: Path) -> None:
    """A repository without a register exits with the missing-input code."""
    assert check_evidence.main(["check", "--root", str(tmp_path)]) == EXIT_MISSING, (
        "exit"
    )


def test_the_command_line_prints_counts_and_exits_one_on_findings(
    tmp_path: Path, make_tree: TreeBuilder, capsys: pytest.CaptureFixture[str]
) -> None:
    """The report names each finding and the counts."""
    root = build(tmp_path, make_tree, doc_with("The entry V099 holds."))
    assert check_evidence.main(["check", "--root", str(root)]) == EXIT_FINDINGS, "exit"
    out = capsys.readouterr().out
    assert "ledger-id" in out, "finding"
    assert "ledger citations: 1" in out, "counts"


def test_the_command_line_takes_the_known_file_and_writes_the_listing(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """``--known`` and ``--listing`` reach the run through the command line."""
    root = build(tmp_path, make_tree, doc_with("The entry V099 holds."))
    entry = {"rule": "ledger-id", "path": DOC_PATH, "key": "V099", "reason": "test"}
    (root / "known.json").write_text(json.dumps([entry]), encoding="utf-8")
    listing = tmp_path / "listing.txt"
    argv = ["check", "--root", str(root), "--known", "known.json"]
    argv += ["--listing", str(listing)]
    assert check_evidence.main(argv) == EXIT_OK, "exit"
    assert not listing.read_text(encoding="utf-8"), "no Resolved gap is named"


def test_the_real_tree_is_read_in_full() -> None:
    """The run sees enough citations that it cannot pass by reading nothing."""
    result = check_evidence.run_check(
        REPO, check_evidence.Options(known=Path("evidence-known.json"))
    )
    assert result.counts["ledger citations"] >= 400, "ledger citations"
    assert result.counts["evidence links"] >= 700, "evidence links"
    assert result.counts["sentences naming a Resolved gap"] > 0, "resolved sentences"
    assert result.phrases["status cell"] > 0, "status cells"
    assert not result.findings, "the real tree, with its known findings"


CITES = st.sampled_from([
    f"[c]({'../' * 2}{CORPUS}/manifest.json)",
    f"`{OTHER}`",
    "V001",
    "M001",
    "GAP-001",
    "GAP-002/003",
    "plain text",
])
SECTION = st.lists(CITES, max_size=4).map(" ".join)
DOCUMENT = st.lists(SECTION, min_size=1, max_size=3).map(
    lambda parts: "\n\n".join(f"## S{i}\n\n{p}" for i, p in enumerate(parts))
)
CORPORA = st.dictionaries(
    st.sampled_from([f"docs/{s}/{n}.md" for s in ("a", "b") for n in ("x", "y", "z")]),
    DOCUMENT,
    min_size=1,
)


ORDERED = CORPORA.flatmap(
    lambda docs: st.tuples(st.just(docs), st.permutations(list(docs)))
)


@given(case=ORDERED)
def test_index_generation_is_independent_of_discovery_order(
    case: tuple[dict[str, str], list[str]],
) -> None:
    """Rendering gives the same bytes however the documents were discovered."""
    documents, order = case
    scanned = {p: evidence_cites.scan_document(p, t) for p, t in documents.items()}
    shuffled = {p: scanned[p] for p in order}
    families = FamilyTable()
    first = evidence_index.render_indexes(
        evidence_index.IndexInputs(scanned, families, {})
    )
    again = evidence_index.render_indexes(
        evidence_index.IndexInputs(shuffled, families, {})
    )
    assert first == again, "order changed the output"
    assert first == evidence_index.render_indexes(
        evidence_index.IndexInputs(scanned, families, {})
    ), "rendering is not repeatable"


def test_the_sample_document_cites_what_the_tests_expect() -> None:
    """Guard the fixture: the alpha document cites one of each kind."""
    cites = evidence_cites.scan_document(DOC_PATH, DOC)
    assert [o.value for o in cites.ledger] == ["V001"], "ledger"
    assert [o.value for o in cites.corpora] == [CORPUS], "corpus"
    assert [o.value for o in cites.scripts] == ["scripts/tool.py"], "script"
