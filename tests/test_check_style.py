"""Tests for the style check (requirements REQ-4 and REQ-5, obligation INV-GLOSSARY)."""

import json
import typing as typ
from pathlib import Path

import check_style
import pytest
import style_layout as sl
import style_prose as sp
from style_helpers import (
    CAPTIONED,
    DIAGRAM,
    FIGURE,
    TABLE,
    build,
)
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from tree_helpers import TreeBuilder

REPO = Path(__file__).resolve().parents[1]
MIN_TABLES = 250
MIN_FIGURES = 10
MIN_GLOSSARY = 60


def _rules(text: str, *, tables_only: bool = False) -> list[str]:
    """List the rule of each layout finding in a document.

    Returns
    -------
    list[str]
        The rules, in order.
    """
    found = sl.layout_findings("d.md", text, tables_only=tables_only).findings
    return [finding.rule for finding in found]


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (CAPTIONED, []),
        (f"{CAPTIONED}\n{CAPTIONED.replace('Table 1', 'Table 2')}", []),
        (f"{TABLE}\n_Table 1: A caption\nthat wraps._\n", []),
        (TABLE, ["table-caption"]),
        (f"{TABLE}\nA plain paragraph.\n", ["table-caption"]),
        (f"{TABLE}\n\n_Table 1: Two blank lines._\n", ["table-caption"]),
        (f"{TABLE}_Table 1: No blank line._\n", ["table-caption"]),
        (f"{TABLE}\n_Table 2: Wrong number._\n", ["table-caption"]),
        (f"{TABLE}\n_Table 1: Unclosed.\n", ["table-caption"]),
        (f"{TABLE}\n_Figure 1: Wrong kind._\n", ["table-caption"]),
        (f"{CAPTIONED}\n{TABLE}", ["table-caption"]),
        (f"```\n{TABLE}```\n", []),
    ],
)
def test_table_caption_rule(text: str, expected: list[str]) -> None:
    """A table needs `_Table N: ..._` after one blank line, numbered from 1."""
    found = sl.layout_findings("d.md", text, tables_only=True).findings
    assert [f.rule for f in found] == expected, "table findings"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        (FIGURE, []),
        (f"{DIAGRAM}\n_Figure 1: Only a caption._\n", ["figure"]),
        (f"For screen readers: text.\n\n{DIAGRAM}", ["figure"]),
        (f"Some other paragraph.\n\n{DIAGRAM}\n_Figure 1: Caption._\n", ["figure"]),
        (f"For screen readers: text.\n\n{DIAGRAM}\n_Figure 2: Caption._\n", ["figure"]),
        (f"For screen readers: text.\n\n{DIAGRAM}\n_Table 1: Wrong._\n", ["figure"]),
        (f"{DIAGRAM}", ["figure", "figure"]),
        (f"{FIGURE}\n{FIGURE.replace('Figure 1', 'Figure 2')}", []),
        (f"{FIGURE}\n{FIGURE}", ["figure"]),
        ("For screen readers: a table follows.\n\n```text\nx\n```\n", []),
    ],
)
def test_figure_rule(text: str, expected: list[str]) -> None:
    """A diagram needs a screen-reader paragraph before and a caption after."""
    assert _rules(text) == expected, "figure findings"


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        ("```python\nx = 1\n```\n", []),
        ("~~~text\nx\n~~~\n", []),
        ("```\nx\n```\n", ["code-fence"]),
        ("~~~\nx\n~~~\n", ["code-fence"]),
        ("```python\nx\n```\n\n```\ny\n```\n", ["code-fence"]),
        ("```\nunclosed\n", ["code-fence"]),
    ],
)
def test_code_fence_rule(text: str, expected: list[str]) -> None:
    """Every fenced block carries a language label."""
    assert _rules(text) == expected, "fence findings"


def test_a_generated_index_is_checked_for_captions_only() -> None:
    """The table rule applies to an index; the fence and figure rules do not."""
    text = f"{TABLE}\n```\nx\n```\n\n{DIAGRAM}"
    assert _rules(text, tables_only=True) == ["table-caption"], "index findings"


@pytest.mark.parametrize(
    ("heading", "wrong", "undecided"),
    [
        ("Context and problem statement", [], []),
        ("The Hotline protocol", [], []),
        ("The wire format of `Filp Record` records", [], []),
        ("Parsing the HTXF header", [], []),
        ("Login (Transaction 107)", [], []),
        ("3. The gates", [], []),
        ("Context And problem", ["And"], []),
        ("Reading The guide", ["The"], []),
        ("Client Initiates", ["Initiates"], []),
        ("2. The Gates", ["Gates"], []),
        ("Field 202: Files paths", [], ["Files"]),
        ("The Sleuthkit", [], ["Sleuthkit"]),
        ("A “Quoted Title” heading", [], ["Quoted", "Title"]),
    ],
)
def test_heading_case_rule(
    heading: str, wrong: list[str], undecided: list[str]
) -> None:
    """Capitalized common words are reported; uncertain ones are only listed."""
    text = f"# {heading}\n\nThe gates and the files, initiates, client and and.\n"
    lower = sp.lowercase_words(text) - {"sleuthkit", "quoted", "title"}
    findings, listed = sp.heading_findings("d.md", text, ({"Hotline"}, lower))
    assert [f.key.rsplit(": ", 1)[-1] for f in findings] == wrong, "findings"
    assert [u.word for u in listed] == undecided, "undecided"


def test_listed_terms_and_phrases_are_not_reported() -> None:
    """A listed word or phrase may be capitalized in a heading."""
    text = "# Reading Sleuth Kit output\n\nThe sleuth and kit.\n"
    lower = sp.lowercase_words(text)
    found, _ = sp.heading_findings("d.md", text, ({"Sleuth Kit"}, lower))
    assert not found, "a listed phrase was reported"
    found, _ = sp.heading_findings("d.md", text, (set(), lower))
    assert [f.key.rsplit(": ", 1)[-1] for f in found] == ["Sleuth", "Kit"], "words"


@pytest.mark.parametrize(
    ("text", "matches"),
    [
        ("The reader selects a row.", []),
        ("We checked the file.", ["We"]),
        ("You can run `we` now.", ["You"]),
        ("Use your own copy.", ["your"]),
        ("Our server and us.", ["Our", "us"]),
        ("I think so.", ["I"]),
        ("Interrupted I/O is not a pronoun.", []),
        ('The US ships and the "I" macro in `I`.', []),
        ("> We are quoted here.", []),
        ('The text "you are banned" is wire text.', []),
        ("```\nwe run\n```\n", []),
        ("The word `our` and [us](us.md) differ.", ["us"]),
        ("Run the step-by-step guide; use-case; me-too.", []),
    ],
)
def test_person_rule(text: str, matches: list[str]) -> None:
    """First and second person are found in prose and nowhere else."""
    found = sp.person_findings("d.md", text)
    assert [f.key.split(":", 1)[0] for f in found] == matches, "matches"


def test_a_person_finding_names_its_context() -> None:
    """The message quotes the line that holds the match."""
    (found,) = sp.person_findings("d.md", "First line.\nWe checked it.\n")
    assert (
        found.render()
        == "d.md:2: person: `We` is first or second person: We checked it."
    ), "render"


def test_a_clean_tree_has_no_findings(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """The synthetic repository is clean, and the counts show it was read."""
    root = build(
        tmp_path, make_tree, {"docs/alpha/t.md": f"# T\n\n{CAPTIONED}\n{FIGURE}"}
    )
    result = check_style.run_check(root)
    assert not result.findings, "unexpected findings"
    assert (result.counts["tables"], result.counts["mermaid blocks"]) == (2, 1), (
        "counts"
    )
    assert result.counts["glossary entries"] == 3, "entries"


def test_scope_skips_generated_pinned_and_record_documents(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Only the table rule reads an index; records and pinned files are skipped."""
    bad = f"# Bad Heading Here\n\nWe say.\n\n{TABLE}\n```\nx\n```\n"
    files = {
        "gap-analysis.md": bad,
        "docs/baseline-validity-ledger.md": bad,
        "docs/documentation-style-guide.md": bad,
        "docs/execplans/plan.md": bad,
        "docs/provenance/records/r.md": bad,
        "docs/provenance/protocol-handoff.md": bad,
        "evidence/x/readme.md": bad,
        "docs/alpha/evidence.md": bad,
        "docs/provenance/README.md": "# Provenance\n\n[glossary](../glossary.md)\n",
    }
    root = build(tmp_path, make_tree, files)
    result = check_style.run_check(root)
    assert [(f.path, f.rule) for f in result.findings] == [
        ("docs/alpha/evidence.md", "table-caption")
    ], "only the index table is reported"


def test_the_root_readme_may_use_the_second_person(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Rule d exempts ``README.md`` and nothing else."""
    root = build(
        tmp_path,
        make_tree,
        {
            "README.md": "# Readme\n\nYou can run it.\n",
            "docs/alpha/n.md": "# N\n\nYou can.\n",
        },
    )
    found = check_style.run_check(root).findings
    assert [(f.path, f.rule) for f in found] == [("docs/alpha/n.md", "person")], (
        "findings"
    )


def test_known_entries_accept_findings_and_stale_ones_are_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """An accepted finding disappears; an entry with no finding is reported."""
    root = build(tmp_path, make_tree, {"docs/alpha/t.md": f"# T\n\n{TABLE}"})
    (finding,) = check_style.run_check(root).findings
    entry = {
        "rule": finding.rule,
        "path": finding.path,
        "key": finding.key,
        "reason": "r",
    }
    stale = {"rule": "person", "path": "docs/alpha/t.md", "key": "x", "reason": "r"}
    known = root / "known.json"
    known.write_text(json.dumps([entry]), encoding="utf-8")
    options = check_style.Options(known=Path("known.json"))
    assert not check_style.run_check(root, options).findings, "not accepted"
    known.write_text(json.dumps([entry, stale]), encoding="utf-8")
    result = check_style.run_check(root, options)
    assert [f.rule for f in result.findings] == ["known"], "stale entry"
    assert len(result.accepted) == 1, "accepted count"


def test_floors_fail_an_empty_run(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """A run that sees fewer tables, diagrams or entries than required fails."""
    root = build(tmp_path, make_tree)
    options = check_style.Options(min_tables=2, min_figures=1, min_glossary=9)
    result = check_style.run_check(root, options)
    assert sorted(f.key for f in result.findings) == [
        "glossary entries",
        "mermaid blocks",
        "tables",
    ], "floors"


def test_listing_holds_undecided_words_and_unlinked_documents(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """The listing file is not a finding but is written for review."""
    files = {"docs/alpha/t.md": "# See Zork\n\nText.\n"}
    root = build(tmp_path, make_tree, files)
    listing = root / "listing.txt"
    result = check_style.run_check(root)
    assert not result.findings, "an undecided word is not a finding"
    code = check_style.main(["check", "--root", str(root), "--listing", str(listing)])
    assert code == EXIT_OK, "exit code"
    text = listing.read_text(encoding="utf-8")
    assert "undecided: docs/alpha/t.md:1: Zork" in text, "undecided"
    assert "unlinked: docs/alpha/t.md" in text, "unlinked"


def test_exit_codes(
    tmp_path: Path, make_tree: TreeBuilder, capsys: pytest.CaptureFixture[str]
) -> None:
    """Success, findings and a missing list exit 0, 1 and 2."""
    root = build(tmp_path, make_tree)
    assert check_style.main(["check", "--root", str(root)]) == EXIT_OK, "clean"
    (root / "docs/alpha/t.md").write_text("# T\n\n" + TABLE, encoding="utf-8")
    assert check_style.main(["check", "--root", str(root)]) == EXIT_FINDINGS, "found"
    out = capsys.readouterr().out
    assert "docs/alpha/t.md:3: table-caption:" in out, "finding line"
    assert "table-caption: 1 findings, 0 accepted" in out, "count per rule"
    (root / "style-terms.txt").unlink()
    assert check_style.main(["check", "--root", str(root)]) == EXIT_MISSING, "missing"


def test_the_real_tree_is_clean_apart_from_known_findings_and_is_not_vacuous() -> None:
    """The run reads enough of the repository, and every finding is accepted."""
    options = check_style.Options(
        known=Path("style-known.json"),
        min_tables=MIN_TABLES,
        min_figures=MIN_FIGURES,
        min_glossary=MIN_GLOSSARY,
    )
    result = check_style.run_check(REPO, options)
    assert [f.render() for f in result.findings] == [], "unaccepted findings"
    assert result.counts["tables"] >= MIN_TABLES, "tables"
    assert result.counts["mermaid blocks"] >= MIN_FIGURES, "mermaid blocks"
    assert result.counts["glossary entries"] >= MIN_GLOSSARY, "glossary entries"
    assert result.counts["required terms"] >= MIN_GLOSSARY, "required terms"
