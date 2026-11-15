"""Tests for the Markdown link gate (obligation INV-LINK)."""

import typing as typ

import check_links
import pytest
from git_helpers import commit_files
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK, MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder

DOC = '# Title\n\n## Second part\n\n<a id="explicit"></a>\n'
SHA = "0123456789abcdef0123456789abcdef01234567"


def test_good_links_pass_and_are_counted(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Files, directories, headings, explicit anchors and URLs all resolve."""
    make_tree(
        tmp_path,
        {
            "a.md": (
                "[f](b.md) [h](b.md#second-part) [x](b.md#explicit) [s](#top)\n"
                "[d](sub/) [u](https://example.com) [m](mailto:a@b.c)\n"
                "[ref]: sub/c.md\n# Top\n"
            ),
            "b.md": DOC,
            "sub/c.md": "text\n",
        },
    )
    report = check_links.check(tmp_path)
    assert not report.failures, f"unexpected failures: {report.failures}"
    assert (report.checked, report.links) == (3, 8), "counts"


def test_links_inside_fences_are_not_checked(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A broken link inside a code fence is ignored."""
    make_tree(tmp_path, {"a.md": "```\n[x](nowhere.md)\n```\n"})
    assert not check_links.check(tmp_path).failures, "fenced link was checked"


@pytest.mark.parametrize(
    ("body", "link"),
    [
        ("[x](nowhere.md)", "nowhere.md"),
        ("[x](b.md#absent)", "b.md#absent"),
        ("[x](#absent)", "#absent"),
        ("[x](../outside.md)", "../outside.md"),
        ("[r]: gone.md", "gone.md"),
    ],
)
def test_broken_links_are_rejected_naming_the_link(
    tmp_path: Path, make_tree: TreeBuilder, body: str, link: str
) -> None:
    """Missing files, missing anchors and escapes fail with the link named."""
    make_tree(tmp_path, {"a.md": f"{body}\n", "b.md": DOC})
    report = check_links.check(tmp_path)
    assert len(report.failures) == 1, f"failures: {report.failures}"
    assert link in report.failures[0], report.failures[0]
    assert "a.md:1" in report.failures[0], report.failures[0]


def test_duplicate_slug_is_ambiguous(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """A fragment that two headings share is rejected as ambiguous."""
    make_tree(
        tmp_path,
        {"a.md": "[x](b.md#notes)\n", "b.md": "# One\n## Notes\n# Two\n## Notes\n"},
    )
    report = check_links.check(tmp_path)
    assert len(report.failures) == 1, f"failures: {report.failures}"
    assert "ambiguous" in report.failures[0], report.failures[0]
    assert "b.md#notes" in report.failures[0], report.failures[0]


def test_explicit_anchor_disambiguates_a_duplicate_slug(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """An explicit ``<a id>`` of the same name makes the fragment unambiguous."""
    make_tree(
        tmp_path,
        {
            "a.md": "[x](b.md#notes)\n",
            "b.md": '<a id="notes"></a>\n## Notes\n## Notes\n',
        },
    )
    assert not check_links.check(tmp_path).failures, "explicit anchor should win"


def test_non_markdown_targets_ignore_fragments(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A fragment on a non-Markdown file is not checked."""
    make_tree(tmp_path, {"a.md": "[x](data.json#whatever)\n", "data.json": "{}\n"})
    assert not check_links.check(tmp_path).failures, "fragment on JSON was checked"


def test_evidence_documents_are_not_scanned(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Markdown under ``evidence/`` is neither read nor counted."""
    make_tree(tmp_path, {"evidence/e.md": "[x](gone.md)\n", "a.md": "text\n"})
    report = check_links.check(tmp_path)
    assert not report.failures, f"failures: {report.failures}"
    assert report.checked == 1, "evidence document was counted"


def test_minimum_links_guards_against_a_vacuous_run(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Fewer links than the stated minimum is itself a failure."""
    make_tree(tmp_path, {"a.md": "[x](a.md)\n"})
    assert not check_links.check(tmp_path, min_links=1).failures, (
        "one link meets minimum one"
    )
    report = check_links.check(tmp_path, min_links=2)
    assert any("at least 2" in failure for failure in report.failures), "no guard"


def test_relative_mothra_link_resolves_against_the_option(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """``../mothra/`` targets are checked inside the given mothra checkout."""
    make_tree(
        tmp_path,
        {
            "repo/a.md": "[ok](../mothra/docs/x.md#head) [bad](../mothra/docs/y.md)\n",
            "mothra/docs/x.md": "# Head\n",
        },
    )
    report = check_links.check(tmp_path / "repo", mothra=tmp_path / "mothra")
    assert len(report.failures) == 1, f"failures: {report.failures}"
    assert "../mothra/docs/y.md" in report.failures[0], report.failures[0]


def test_relative_mothra_link_without_option_is_a_missing_input(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Without ``mothra`` the link cannot be checked, which is exit code 2."""
    make_tree(tmp_path, {"a.md": "[x](../mothra/docs/x.md)\n"})
    with pytest.raises(MissingInputError, match="mothra"):
        check_links.check(tmp_path / ".", mothra=None)


def test_forbid_switch_rejects_relative_mothra_links(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """With the switch on, the link fails even when its target exists."""
    make_tree(
        tmp_path,
        {"repo/a.md": "[ok](../mothra/docs/x.md)\n", "mothra/docs/x.md": "# H\n"},
    )
    report = check_links.check(
        tmp_path / "repo", mothra=tmp_path / "mothra", forbid_relative_mothra=True
    )
    assert len(report.failures) == 1, f"failures: {report.failures}"
    assert "../mothra/docs/x.md" in report.failures[0], report.failures[0]
    assert "relative link into mothra" in report.failures[0], report.failures[0]


def mothra_repo(tmp_path: Path) -> tuple[Path, str]:
    """Create a mothra clone with one committed file.

    Returns
    -------
    tuple[pathlib.Path, str]
        The clone and its commit identifier.
    """
    clone = tmp_path / "mothra"
    clone.mkdir()
    return clone, commit_files(clone, {"docs/x.md": "# H\n"})


def test_permalink_to_an_existing_path_passes(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A ``blob/<sha>/<path>`` link whose path exists at that commit passes."""
    clone, sha = mothra_repo(tmp_path)
    link = f"https://github.com/leynos/mothra/blob/{sha}/docs/x.md#L1"
    make_tree(tmp_path, {"repo/a.md": f"[x]({link})\n"})
    report = check_links.check(
        tmp_path / "repo", mothra=clone, forbid_relative_mothra=True
    )
    assert not report.failures, f"failures: {report.failures}"


@pytest.mark.parametrize(
    ("template", "word"),
    [
        (
            "https://github.com/leynos/mothra/blob/main/docs/x.md",
            "not a commit permalink",
        ),
        ("https://github.com/leynos/mothra/blob/{sha}/docs/absent.md", "absent at"),
        (f"https://github.com/leynos/mothra/blob/{SHA}/docs/x.md", "absent at"),
        ("https://github.com/leynos/mothra", "not a commit permalink"),
    ],
)
def test_bad_mothra_github_links_are_rejected(
    tmp_path: Path, make_tree: TreeBuilder, template: str, word: str
) -> None:
    """Branch-named links and permalinks to absent paths fail, naming the link."""
    clone, sha = mothra_repo(tmp_path)
    link = template.format(sha=sha)
    make_tree(tmp_path, {"repo/a.md": f"[x]({link})\n"})
    report = check_links.check(
        tmp_path / "repo", mothra=clone, forbid_relative_mothra=True
    )
    assert len(report.failures) == 1, f"failures: {report.failures}"
    assert link in report.failures[0], report.failures[0]
    assert word in report.failures[0], report.failures[0]


def test_github_links_are_not_policed_when_the_switch_is_off(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Without the switch a mothra GitHub URL is an ordinary external link."""
    make_tree(tmp_path, {"a.md": "[x](https://github.com/leynos/mothra/blob/main/x)\n"})
    assert not check_links.check(tmp_path).failures, "external link was policed"


def test_permalink_without_a_clone_is_a_missing_input(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Verifying a permalink needs the clone; without it the run is exit 2."""
    link = f"https://github.com/leynos/mothra/blob/{SHA}/x.md"
    make_tree(tmp_path, {"a.md": f"[x]({link})\n"})
    with pytest.raises(MissingInputError, match="clone"):
        check_links.check(tmp_path, forbid_relative_mothra=True)


def test_main_exit_codes_and_summary_line(
    tmp_path: Path, make_tree: TreeBuilder, capsys: pytest.CaptureFixture[str]
) -> None:
    """The CLI ends with ``N documents, M links, K failures`` and exits 0, 1 or 2."""
    make_tree(tmp_path, {"a.md": "[x](a.md)\n"})
    assert check_links.main(["--root", str(tmp_path)]) == EXIT_OK, "clean run"
    last = capsys.readouterr().out.splitlines()[-1]
    assert last == "1 documents, 1 links, 0 failures", last
    make_tree(tmp_path, {"b.md": "[x](gone.md)\n"})
    assert check_links.main(["--root", str(tmp_path)]) == EXIT_FINDINGS, "findings"
    last = capsys.readouterr().out.splitlines()[-1]
    assert last == "2 documents, 2 links, 1 failures", last
    assert check_links.main(["--root", str(tmp_path / "none")]) == EXIT_MISSING, (
        "missing"
    )
