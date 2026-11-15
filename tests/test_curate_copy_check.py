"""Tests for copying and checking the curated evidence import (INV-IMPORT)."""

import dataclasses as dc
import typing as typ

import curate_check
import curate_copy
import curate_evidence
import curate_select
import curation_helpers as ch
import pytest
from evidence_files import CitingRoot
from git_helpers import init_repo
from repo_files import git
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK

if typ.TYPE_CHECKING:
    from pathlib import Path

CITED = (
    f"{ch.PM1}/data.bin {ch.PM2}/data.json {ch.INPUTS}/notes.txt "
    f"{ch.LOOSE} {ch.WITHHELD_PATH}"
)


@dc.dataclass(slots=True)
class World:
    """A source repository, its curation and an imported destination.

    Attributes
    ----------
    source : Path
        The source repository.
    commit : str
        Its commit.
    root : Path
        The destination that ``copy`` filled.
    document : Path
        A document whose citations resolve.
    """

    source: Path
    commit: str
    root: Path
    document: Path


def world(tmp_path: Path) -> World:
    """Build the source, select, and copy into a destination.

    Returns
    -------
    World
        The three roots and the commit.
    """
    source = tmp_path / "source"
    ch.write_tree(source, ch.SOURCE)
    init_repo(source)
    commit = (
        git("-C", str(source), "rev-parse", "HEAD").run_sync().stdout or ""
    ).strip()
    document = tmp_path / "doc.md"
    document.write_text(CITED, encoding="utf-8")
    withheld = ch.write_withheld(tmp_path)
    selection = curate_select.select(
        curate_select.SelectRequest(
            source, (CitingRoot("document", document),), withheld, commit
        )
    )
    root = tmp_path / "dest"
    (root / "evidence").mkdir(parents=True)
    (root / "evidence/curation.json").write_text(
        curate_select.selection_text(selection), encoding="utf-8"
    )
    (root / "evidence/withheld.json").write_bytes(withheld.read_bytes())
    curate_copy.copy_evidence(curate_copy.CopyRequest(source, root))
    return World(source, commit, root, document)


def check(w: World, *, local: tuple[str, ...] = ()) -> curate_check.CheckResult:
    """Run the full check, with the source comparison.

    Returns
    -------
    curate_check.CheckResult
        The result.
    """
    return curate_check.check(
        curate_check.CheckRequest(
            root=w.root,
            citing=(CitingRoot("document", w.document),),
            source_root=w.source,
            source_commit=w.commit,
            local_files=local,
        )
    )


def test_copy_skips_the_withheld_and_the_excluded_and_keeps_bytes(
    tmp_path: Path,
) -> None:
    """Included files arrive byte for byte; withheld and excluded ones do not."""
    w = world(tmp_path)
    assert (w.root / ch.PM1 / "data.bin").read_bytes() == b"\r\n\x00binary\xff", "bytes"
    assert (w.root / ch.ODD_NAME).read_bytes() == b"odd", "control-character name"
    assert (w.root / ch.BAD_NAME).read_bytes() == b"not utf-8", "name that is not UTF-8"
    assert not (w.root / ch.WITHHELD_PATH).exists(), "the fork is withheld"
    assert not (w.root / ch.NOISE).exists(), "an excluded corpus is not copied"
    assert not (w.root / "evidence/runtime-network").exists(), "another project's"


def test_copy_preserves_the_executable_bit_and_is_idempotent(tmp_path: Path) -> None:
    """A second copy changes nothing and counts every file as identical."""
    source = tmp_path / "source"
    ch.write_tree(source, ch.SOURCE)
    (source / ch.PM1 / "data.bin").chmod(0o755)
    document = tmp_path / "d.md"
    document.write_text(CITED, encoding="utf-8")
    withheld = ch.write_withheld(tmp_path)
    citing = (CitingRoot("document", document),)
    selection = curate_select.select(
        curate_select.SelectRequest(source, citing, withheld, "c")
    )
    root = tmp_path / "dest"
    (root / "evidence").mkdir(parents=True)
    (root / "evidence/curation.json").write_text(
        curate_select.selection_text(selection), encoding="utf-8"
    )
    request = curate_copy.CopyRequest(source, root, withheld)
    first = curate_copy.copy_evidence(request)
    again = curate_copy.copy_evidence(request)
    assert (again.copied, again.identical) == (0, first.copied), (first, again)
    assert first.withheld == 1, first
    assert (root / ch.PM1 / "data.bin").stat().st_mode & 0o111, "executable bit"
    assert not (root / ch.PM1 / "SHA256SUMS").stat().st_mode & 0o111, "plain file"


def test_copy_refuses_to_overwrite_a_differing_file_and_copies_nothing(
    tmp_path: Path,
) -> None:
    """A conflict aborts before any file is written."""
    w = world(tmp_path)
    (w.root / ch.PM1 / "data.bin").write_bytes(b"different")
    (w.root / ch.PM2 / "data.json").unlink()
    with pytest.raises(curate_copy.CopyConflictError, match=r"data\.bin"):
        curate_copy.copy_evidence(curate_copy.CopyRequest(w.source, w.root))
    assert not (w.root / ch.PM2 / "data.json").exists(), "nothing may be copied"


def test_a_faithful_import_has_no_differences(tmp_path: Path) -> None:
    """Corpora, citations and content all agree."""
    result = check(world(tmp_path))
    assert not result.failures, result.failures
    assert result.differences == 0, result
    assert result.compared >= 8, result


def test_an_altered_file_is_a_difference(tmp_path: Path) -> None:
    """One changed byte is found and named."""
    w = world(tmp_path)
    (w.root / ch.PM1 / "data.bin").write_bytes(b"\r\n\x00binarX\xff")
    result = check(w)
    assert result.differences == 1, result.failures
    assert "data.bin" in result.failures[0], result.failures


def test_a_missing_file_is_a_difference(tmp_path: Path) -> None:
    """A file of an included corpus that is absent is found and named."""
    w = world(tmp_path)
    (w.root / ch.ODD_NAME).unlink()
    result = check(w)
    assert result.differences == 1, result.failures
    assert "missing" in result.failures[0], result.failures


def test_an_extra_file_is_a_difference_unless_allowed(tmp_path: Path) -> None:
    """A file the source lacks fails, except the curation allow-list."""
    w = world(tmp_path)
    extra = f"{ch.PM1}/extra.txt"
    (w.root / extra).write_text("extra", encoding="utf-8")
    (w.root / "evidence/gap-remediation/2026-11-13/native-pm-01/p.bsdiff").write_text(
        "x"
    )
    result = check(w)
    assert result.differences == 1, result.failures
    assert extra in result.failures[0], result.failures
    assert not check(w, local=(extra,)).failures, "allow-listed local file"


def test_corpus_sets_must_match_the_included_set(tmp_path: Path) -> None:
    """An excluded corpus present, or an included one absent, is a failure."""
    w = world(tmp_path)
    (w.root / ch.NOISE).mkdir(parents=True)
    (w.root / ch.NOISE / "x.txt").write_text("noise", encoding="utf-8")
    messages = " ".join(check(w).failures)
    assert f"{ch.NOISE}: present but not included" in messages, messages
    (w.root / ch.PM2 / "data.json").unlink()
    (w.root / ch.ODD_NAME).unlink()
    (w.root / ch.BAD_NAME).unlink()
    assert f"{ch.PM2}: included but absent" in " ".join(check(w).failures), "absent"


def test_unresolved_citations_are_listed(tmp_path: Path) -> None:
    """A cited path that does not exist, and is not withheld, is a failure."""
    w = world(tmp_path)
    w.document.write_text(f"{CITED} {ch.PM1}/gone.txt {ch.PM1}/", encoding="utf-8")
    failures = check(w).failures
    assert any(
        f"{ch.PM1}/gone.txt" in f and "does not resolve" in f for f in failures
    ), failures
    assert not any(ch.WITHHELD_PATH in f for f in failures), "a withheld path resolves"


def test_a_path_template_resolves_by_prefix(tmp_path: Path) -> None:
    """A citation cut short at a format placeholder names a family of files.

    A script that builds ``.../queries/D-{address}.c`` is read as citing
    ``.../queries/D-``. That resolves when some file begins with it, and fails
    when none does.
    """
    w = world(tmp_path)
    (w.root / ch.PM1 / "D-1000.c").write_text("x", encoding="utf-8")
    w.document.write_text(
        f"{CITED} {ch.PM1}/D-{{address}}.c {ch.PM1}/E-{{address}}.c", encoding="utf-8"
    )
    failures = [f for f in check(w).failures if "does not resolve" in f]
    assert len(failures) == 1, failures
    assert f"{ch.PM1}/E-" in failures[0], failures


LOCAL_CORPUS = "evidence/protocol-gap-analysis/2026-11-15/revision-90"


def test_a_corpus_created_here_must_be_declared_local(tmp_path: Path) -> None:
    """A corpus that the source never held passes only when recorded as local."""
    w = world(tmp_path)
    (w.root / LOCAL_CORPUS).mkdir(parents=True)
    (w.root / LOCAL_CORPUS / "manifest.json").write_text("{}\n", encoding="utf-8")
    undeclared = " ".join(check(w).failures)
    assert f"{LOCAL_CORPUS}: present but not included" in undeclared, undeclared
    assert "absent from the source commit" in undeclared, undeclared
    (w.root / curate_check.LOCAL_RELATIVE).write_text(
        '{"schema_version": 1, "corpora": [{"path": "'
        + LOCAL_CORPUS
        + '", "reason": "audit revision cut here"}]}\n',
        encoding="utf-8",
    )
    declared = check(w).failures
    assert not declared, declared


def test_command_line_exit_codes(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """``check`` exits 0 when faithful, 1 on a difference, 2 on a missing root."""
    w = world(tmp_path)
    argv = ["check", "--root", str(w.root), "--citing", f"document={w.document}"]
    argv += ["--source-root", str(w.source), "--source-commit", w.commit]
    assert curate_evidence.main(argv) == EXIT_OK, capsys.readouterr().out
    assert "files compared, 0 differences" in capsys.readouterr().out, "summary"
    (w.root / ch.PM1 / "data.bin").write_bytes(b"x")
    assert curate_evidence.main(argv) == EXIT_FINDINGS, "an altered file"
    absent = ["check", "--root", str(tmp_path / "absent")]
    assert curate_evidence.main(absent) == EXIT_MISSING, "no root"


def test_select_and_copy_commands_round_trip(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    """The ``select`` and ``copy`` commands parse their options and agree."""
    source = tmp_path / "source"
    ch.write_tree(source, ch.SOURCE)
    document = tmp_path / "doc.md"
    document.write_text(CITED, encoding="utf-8")
    withheld = ch.write_withheld(tmp_path)
    root = tmp_path / "dest"
    (root / "evidence").mkdir(parents=True)
    curation = root / "evidence/curation.json"
    select = ["select", "--source-root", str(source), "--output", str(curation)]
    select += ["--citing", f"document={document}", "--withheld", str(withheld)]
    assert curate_evidence.main(select) == EXIT_OK, capsys.readouterr().out
    assert " included (" in capsys.readouterr().out, "totals are printed"
    copy = ["copy", str(source), "--root", str(root), "--withheld", str(withheld)]
    assert curate_evidence.main(copy) == EXIT_OK, "copy"
    assert "1 withheld skipped" in capsys.readouterr().out, "withheld count"
    assert (root / ch.PM1 / "data.bin").is_file(), "copied"
