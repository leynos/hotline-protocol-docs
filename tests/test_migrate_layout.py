"""Tests for the document relocation tool (obligation INV-MOVE)."""

import collections as col
import json
import typing as typ
from pathlib import Path, PurePosixPath
from pathlib import PurePosixPath as P

import check_links
import layout_helpers as lh
import layout_register as lreg
import layout_rewrite as lrw
import layout_verify as lv
import markdown_model as mm
import migrate_layout as ml
import pytest
from git_helpers import commit_files
from hypothesis import find, given, settings
from hypothesis.errors import NoSuchExample
from repo_files import git
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from tree_helpers import TreeBuilder

SETTINGS = settings(max_examples=600, derandomize=True, database=None, deadline=None)
MIN_SEEN = 25


def moves_of(pairs: dict[str, str]) -> dict[PurePosixPath, PurePosixPath]:
    """Build a move map of pure paths.

    Parameters
    ----------
    pairs : dict[str, str]
        Old path to new path.

    Returns
    -------
    dict[pathlib.PurePosixPath, pathlib.PurePosixPath]
        The move map.
    """
    return {P(old): P(new) for old, new in pairs.items()}


def test_rewritten_links_reach_the_moved_counterpart() -> None:
    """For any source, target and move map the new link resolves to the old one."""
    seen: col.Counter[str] = col.Counter()

    @SETTINGS
    @given(lh.cases())
    def prop(case: lh.Case) -> None:
        """Check one case and count what it exercises."""
        rewritten = lrw.rewrite_link(case.link, case.source, case.moves)
        assert lh.oracle(case, rewritten), (case, rewritten)
        seen.update(lh.classify(case))
        seen["rewritten"] += rewritten != case.link
        seen["kept"] += rewritten == case.link

    prop()
    for name in ("deeper", "shallower", "source moved", "target moved", "to directory"):
        assert seen[name] >= MIN_SEEN, f"generator is vacuous for {name}: {seen}"
    assert seen["rewritten"] >= MIN_SEEN, f"nothing was rewritten: {seen}"
    assert seen["kept"] >= MIN_SEEN, f"nothing was kept: {seen}"


def test_a_rewriter_that_returns_its_input_fails_the_property() -> None:
    """The negative control: an identity rewriter has a counterexample."""
    found = find(
        lh.cases(),
        lambda case: not lh.oracle(case, case.link),
        settings=SETTINGS,
    )
    assert found.link, "no counterexample"


def test_the_control_would_pass_a_correct_rewriter() -> None:
    """The same search finds nothing against the real rewriter."""
    with pytest.raises(NoSuchExample):
        find(
            lh.cases(),
            lambda c: not lh.oracle(c, lrw.rewrite_link(c.link, c.source, c.moves)),
            settings=settings(SETTINGS, max_examples=200),
        )


@pytest.mark.parametrize(
    ("link", "source", "moves", "expected"),
    [
        ("b.md#sec", "a.md", {"b.md": "docs/b.md"}, "docs/b.md#sec"),
        ("b.md", "a.md", {"a.md": "docs/s/a.md"}, "../../b.md"),
        ("b.md", "a.md", {"a.md": "d/a.md", "b.md": "d/b.md"}, "b.md"),
        ("./b.md", "a.md", {"a.md": "d/a.md", "b.md": "d/b.md"}, "./b.md"),
        (
            "../evidence/x.c",
            "docs/l.md",
            {"docs/l.md": "docs/p/l.md"},
            "../../evidence/x.c",
        ),
        ("evidence/", "a.md", {"a.md": "docs/a.md"}, "../evidence/"),
        ("../../b.md", "docs/p/a.md", {"b.md": "docs/b.md"}, "../b.md"),
        ("../mothra/x.md", "a.md", {"a.md": "docs/s/a.md"}, "../../../mothra/x.md"),
        ("my%20doc.md", "a.md", {"my doc.md": "docs/my doc.md"}, "docs/my%20doc.md"),
        ("a.md#x", "a.md", {"a.md": "docs/a.md"}, "a.md#x"),
        ("#local", "a.md", {"a.md": "docs/a.md"}, "#local"),
        ("https://x.org/a.md", "a.md", {"a.md": "docs/a.md"}, "https://x.org/a.md"),
        ("mailto:a@b.c", "a.md", {"a.md": "docs/a.md"}, "mailto:a@b.c"),
        ("/abs/a.md", "a.md", {"a.md": "docs/a.md"}, "/abs/a.md"),
    ],
)
def test_single_links(
    link: str, source: str, moves: dict[str, str], expected: str
) -> None:
    """Fragments, depth changes, directories, encodings and non-files behave."""
    table = {P(k): P(v) for k, v in moves.items()}
    assert lrw.rewrite_link(link, P(source), table) == expected, "rewritten link"


def test_text_forms_are_preserved_and_code_is_left_alone() -> None:
    """Titles, reference definitions and line endings survive; fences and spans stay."""
    text = (
        '# T\r\n[a](b.md "Title") and [c](b.md#f) end\r\n'
        "[ref]: b.md 'Tip'\r\n`[x](b.md)` outside\r\n"
        "```\r\n[y](b.md)\r\n```\r\nb.md plain\r\n"
    )
    new, changes = lrw.rewrite_text(text, P("a.md"), moves_of({"b.md": "docs/b.md"}))
    expected = (
        '# T\r\n[a](docs/b.md "Title") and [c](docs/b.md#f) end\r\n'
        "[ref]: docs/b.md 'Tip'\r\n`[x](b.md)` outside\r\n"
        "```\r\n[y](b.md)\r\n```\r\nb.md plain\r\n"
    )
    assert new == expected, "text after rewrite"
    assert [c.line for c in changes] == [2, 2, 3], "changed lines"


def test_a_corrupted_document_is_caught_by_the_check() -> None:
    """The INV-MOVE check names a changed prose line, a heading and a bad link."""
    moves = moves_of({"b.md": "docs/b.md"})
    old = "# Head\n\nprose [x](b.md)\n"
    good = lv.verify_document(old, "# Head\n\nprose [x](docs/b.md)\n", P("a.md"), moves)
    assert not good, good
    prose = lv.verify_document(
        old, "# Head\n\nprosy [x](docs/b.md)\n", P("a.md"), moves
    )
    assert len(prose) == 1, prose
    title = lv.verify_document(
        old, "# Other\n\nprose [x](docs/b.md)\n", P("a.md"), moves
    )
    assert any("heading" in message for message in title), title
    unchanged = lv.verify_document(old, old, P("a.md"), moves)
    assert any("reaches elsewhere" in message for message in unchanged), unchanged


REGISTER: dict[str, typ.Any] = json.loads(lh.TREE["gap-register.json"])


def test_the_register_follows_embedded_links_but_not_paths_by_default() -> None:
    """Embedded links are rewritten; structured paths wait for the refresh."""
    moves = moves_of({"a.md": "docs/a.md", "b.md": "docs/b.md"})
    new, count = lreg.rewrite_register(REGISTER, P("gap-analysis.md"), moves)
    assert count == 1, count
    gap = new["gaps"][0]
    evidence = gap["resolution"]["evidence"]
    assert evidence == ["[A](docs/a.md#a) and [E](evidence/x.txt)"], evidence
    assert gap["sources"][0]["path"] == "a.md", "path should wait for the refresh"
    assert gap["question"] == REGISTER["gaps"][0]["question"], "protected field"


def test_the_register_paths_are_rewritten_on_request() -> None:
    """With ``paths`` the sources and the coverage follow the move."""
    moves = moves_of({"a.md": "docs/a.md", "b.md": "docs/b.md"})
    new, _ = lreg.rewrite_register(REGISTER, P("gap-analysis.md"), moves, paths=True)
    assert new["gaps"][0]["sources"][0]["path"] == "docs/a.md", "source path"
    assert new["review_coverage"][0]["path"] == "docs/b.md", "coverage path"


def test_a_link_in_a_protected_field_stops_the_run() -> None:
    """A protected field that would need editing is reported, never edited."""
    register = json.loads(json.dumps(REGISTER))
    register["gaps"][0]["closure_criteria"] = "Publish [it](a.md)."
    with pytest.raises(lreg.ProtectedFieldError, match="closure_criteria"):
        lreg.rewrite_register(
            register, P("gap-analysis.md"), moves_of({"a.md": "docs/a.md"})
        )


def build(tmp_path: Path, moves: dict[str, str]) -> tuple[Path, Path]:
    """Create the sample repository and its move map.

    Parameters
    ----------
    tmp_path : pathlib.Path
        The test directory.
    moves : dict[str, str]
        Old path to new path.

    Returns
    -------
    tuple[pathlib.Path, pathlib.Path]
        The repository root and the move map.
    """
    repo = tmp_path / "repo"
    repo.mkdir()
    commit_files(repo, lh.TREE)
    path = tmp_path / "moves.json"
    path.write_text(json.dumps({"moves": moves, "flagged": {}}), encoding="utf-8")
    return repo, path


def args(repo: Path, moves: Path, *extra: str) -> list[str]:
    """Build the command-line tail common to every subcommand.

    Parameters
    ----------
    repo : pathlib.Path
        The repository root.
    moves : pathlib.Path
        The move map.
    *extra : str
        Further tokens.

    Returns
    -------
    list[str]
        The tokens.
    """
    return ["--root", str(repo), "--moves", str(moves), *extra]


def test_a_missing_source_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A source that is not there is a missing input and nothing moves."""
    repo, moves = build(tmp_path, {"gone.md": "docs/gone.md"})
    assert ml.main(["plan", *args(repo, moves)]) == EXIT_MISSING, "plan exit"
    assert ml.main(["apply", *args(repo, moves)]) == EXIT_MISSING, "apply exit"
    assert "gone.md" in capsys.readouterr().err, "message names the source"
    assert (repo / "a.md").is_file(), "tree untouched"


def test_an_existing_destination_is_refused(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """A destination that exists is a refusal and nothing moves."""
    repo, moves = build(tmp_path, {"a.md": "b.md"})
    assert ml.main(["plan", *args(repo, moves)]) == EXIT_FINDINGS, "plan exit"
    assert ml.main(["apply", *args(repo, moves)]) == EXIT_FINDINGS, "apply exit"
    assert "b.md" in capsys.readouterr().err, "message names the destination"


def test_plan_reports_classes_and_changes_nothing(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The dry run counts rewrites by class and lists the names that stay."""
    repo, moves = build(tmp_path, lh.MOVES)
    assert ml.main(["plan", *args(repo, moves)]) == EXIT_OK, "plan exit"
    out = capsys.readouterr().out
    lines = {line.strip() for line in out.splitlines()}
    expected = {
        "links rewritten: 8 (reference definitions: 1)",
        "moved -> evidence/: 2",
        "moved -> moved document: 3",
        "unmoved -> moved document: 3",
        "evidence (hashed, untouched): 2",
        "fenced code: 1",
        "prose: 1",
        "code span: 1",
    }
    assert expected <= lines, f"missing {sorted(expected - lines)}"
    assert (repo / "a.md").is_file(), "plan moved a file"


def test_apply_moves_and_rewrites_without_changing_anything_else(
    tmp_path: Path,
) -> None:
    """End to end on a real repository: renames, link-only edits, links resolve."""
    repo, moves = build(tmp_path, lh.MOVES)
    before = {
        n: (repo / n).read_bytes()
        for n in ("evidence/x.txt", "evidence/n.md", "gap-analysis.md")
    }
    assert ml.main(["apply", *args(repo, moves)]) == EXIT_OK, "apply exit"
    diff = git("-C", str(repo), "diff", "--cached", "-M", "--name-status").run_sync()
    renames = [x for x in (diff.stdout or "").splitlines() if x.startswith("R")]
    assert len(renames) == len(lh.MOVES), diff.stdout
    for old, new in lh.MOVES.items():
        old_text, new_text = lh.TREE[old], (repo / new).read_text(encoding="utf-8")
        assert not (repo / old).exists(), f"{old} remains"
        assert [s["heading"] for s in mm.section_inventory(old_text)] == [
            s["heading"] for s in mm.section_inventory(new_text)
        ], f"{old} headings"
        assert lh.lines_without_links(old_text) == lh.lines_without_links(new_text), old
    failures = check_links.check(repo).failures
    assert [f.split(":")[0] for f in failures] == ["gap-analysis.md"], failures
    assert {n: (repo / n).read_bytes() for n in before} == before, (
        "evidence or generated file touched"
    )
    moved = (repo / "docs/one/a.md").read_text(encoding="utf-8")
    assert "```\n[b](b.md)\n```" in moved, "the fenced link must stay"


def test_apply_follows_the_register_but_leaves_paths_for_the_refresh(
    tmp_path: Path,
) -> None:
    """Embedded register links follow the move; structured paths do not."""
    repo, moves = build(tmp_path, lh.MOVES)
    assert ml.main(["apply", *args(repo, moves)]) == EXIT_OK, "apply exit"
    register = json.loads((repo / "gap-register.json").read_text(encoding="utf-8"))
    link = register["gaps"][0]["resolution"]["evidence"][0]
    assert link.startswith("[A](docs/one/a.md#a)"), link
    assert register["gaps"][0]["sources"][0]["path"] == "a.md", (
        "paths wait for the refresh"
    )


def test_a_moved_generated_file_is_left_for_the_renderer(tmp_path: Path) -> None:
    """The generated report moves but is neither rewritten nor verified."""
    repo, moves = build(tmp_path, {**lh.MOVES, "gap-analysis.md": "docs/gap.md"})
    assert ml.main(["apply", *args(repo, moves)]) == EXIT_OK, "apply exit"
    moved = (repo / "docs/gap.md").read_text(encoding="utf-8")
    assert moved == lh.TREE["gap-analysis.md"], (
        "generated text must wait for the renderer"
    )


def test_apply_reports_a_violation_and_leaves_the_tree(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    """A rewriter that does nothing makes apply fail loudly with the tree left."""
    repo, moves = build(tmp_path, lh.MOVES)
    monkeypatch.setattr("layout_scan.rewrite_text", lambda text, _s, _m: (text, []))
    assert ml.main(["apply", *args(repo, moves)]) == EXIT_FINDINGS, "apply exit"
    assert "INV-MOVE violated" in capsys.readouterr().out, "no violation reported"
    assert (repo / "docs/one/a.md").is_file(), "tree must stay for inspection"


def test_section_map_names_every_moved_document(tmp_path: Path) -> None:
    """The map holds old-to-new file names for Markdown only."""
    repo, moves = build(tmp_path, {**lh.MOVES, "gap-register.json": "docs/r.json"})
    out = tmp_path / "map.json"
    code = ml.main(["section-map", *args(repo, moves, "--out", str(out))])
    assert code == EXIT_OK, "section-map exit"
    assert json.loads(out.read_text(encoding="utf-8")) == {"files": lh.MOVES}, "map"


def test_flagged_moves_are_opt_in(tmp_path: Path) -> None:
    """A flagged move is carried out only when asked for."""
    repo, moves = build(tmp_path, {})
    moves.write_text(
        json.dumps({"moves": {}, "flagged": {"a.md": "docs/a.md"}}), "utf-8"
    )
    assert ml.load_moves(moves, [], everything=False) == {}, "not asked for"
    chosen = ml.load_moves(moves, ["a.md"], everything=False)
    assert chosen == {P("a.md"): P("docs/a.md")}, "included by name"
    every = ml.load_moves(moves, [], everything=True)
    assert every == {P("a.md"): P("docs/a.md")}, "included by all-flagged"
    code = ml.main(["plan", *args(repo, moves, "--include", "nope.md")])
    assert code == EXIT_MISSING, "unknown flagged move"


def test_typos_configuration_paths_are_followed(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Exact quoted paths in typos.local.toml follow a moved file."""
    make_tree(
        tmp_path, {"typos.local.toml": 'exclude = ["a.md", "keep.md"]\n', "a.md": "x\n"}
    )
    done = ml.compute(tmp_path, moves_of({"a.md": "docs/a.md"}))
    new = done.texts[P("typos.local.toml")]
    assert new == 'exclude = ["docs/a.md", "keep.md"]\n', new


def test_the_real_move_map_is_complete_and_well_formed() -> None:
    """Every tracked root document but AGENTS.md has one destination, once."""
    repo = Path(__file__).resolve().parents[1]
    data = json.loads(ml.DEFAULT_MOVES.read_text(encoding="utf-8"))
    moves = {**data["moves"], **data["flagged"]}
    roots = {p.name for p in repo.glob("*.md")} - {"AGENTS.md", "README.md"}
    assert roots <= set(moves), f"unplaced: {sorted(roots - set(moves))}"
    assert len(set(moves.values())) == len(moves), "destinations repeat"
    assert all(
        n.rsplit("/", 1)[-1] == o.rsplit("/", 1)[-1] for o, n in moves.items()
    ), "renamed"
