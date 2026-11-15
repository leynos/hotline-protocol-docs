"""Tests for the ``SHA256SUMS`` verifier (obligation INV-IMPORT)."""

import json
import typing as typ

import check_sums
import curate_select
import curation_helpers as ch
import pytest
from tool_support import EXIT_FINDINGS, EXIT_MISSING, EXIT_OK
from withheld_helpers import (
    FORK,
    FORK_PATH,
    digest,
    entry,
    manifest_text,
    write_mothra_manifest,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder

CORPUS = "evidence/gap-remediation/2026-11-13/native-pm-01"
SUMS = f"{CORPUS}/SHA256SUMS"
DATA = b"captured bytes\n"


def line(data: bytes, name: str, mark: str = " ") -> str:
    """Return one sums line for ``data`` named ``name``.

    Returns
    -------
    str
        ``<sha256> <mark><name>`` with the text-mode or binary-mode marker.
    """
    return f"{digest(data)} {mark}{name}\n"


def run(root: Path, **options: Path) -> check_sums.SumsReport:
    """Run the verifier below ``root``.

    Returns
    -------
    check_sums.SumsReport
        The report.
    """
    return check_sums.check(check_sums.SumsRequest(root=root, **options))


def test_root_relative_entries_verify(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """The ``evidence/…`` convention verifies from the repository root."""
    make_tree(
        tmp_path,
        {f"{CORPUS}/a.txt": DATA, SUMS: line(DATA, f"{CORPUS}/a.txt", "*")},
    )
    report = run(tmp_path)
    assert not report.failures, report.failures
    assert (report.files, report.ok) == (1, 1), report
    assert report.summary() == (
        "1 sums files, 1 entries: 1 ok, 0 withheld, 0 not imported, 0 external, "
        "0 failures"
    ), report.summary()


def test_directory_relative_entries_verify(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Bare names resolve against the sums file's own directory."""
    make_tree(tmp_path, {f"{CORPUS}/sub/a.txt": DATA, SUMS: line(DATA, "sub/a.txt")})
    report = run(tmp_path)
    assert not report.failures, report.failures
    assert report.ok == 1, report


def test_a_file_that_mixes_conventions_is_reported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Both conventions in one sums file are noted, though both verify."""
    make_tree(
        tmp_path,
        {
            f"{CORPUS}/a.txt": DATA,
            f"{CORPUS}/b.txt": DATA,
            SUMS: line(DATA, f"{CORPUS}/a.txt") + line(DATA, "b.txt"),
        },
    )
    report = run(tmp_path)
    assert report.ok == 2, report
    assert any("mixes" in note and SUMS in note for note in report.notes), report.notes


def test_a_mismatch_is_a_failure_naming_the_path(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Altered content fails, and the message names the sums file and path."""
    make_tree(tmp_path, {f"{CORPUS}/a.txt": b"changed", SUMS: line(DATA, "a.txt")})
    report = run(tmp_path)
    assert len(report.failures) == 1, report.failures
    assert "a.txt" in report.failures[0], report.failures[0]
    assert "mismatch" in report.failures[0], report.failures[0]


def test_a_missing_file_in_an_included_corpus_fails(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A listed file that is absent is a failure."""
    make_tree(tmp_path, {SUMS: line(DATA, "gone.txt")})
    report = run(tmp_path)
    assert any("missing" in f and "gone.txt" in f for f in report.failures), (
        report.failures
    )


def test_a_withheld_entry_is_counted_when_absent(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A withheld file need not exist; it is counted, not failed."""
    manifest = manifest_text([entry(FORK_PATH, FORK)])
    make_tree(
        tmp_path,
        {
            "evidence/withheld.json": manifest,
            "evidence/inputs/SHA256SUMS": line(FORK, FORK_PATH),
        },
    )
    report = run(tmp_path)
    assert not report.failures, report.failures
    assert (report.withheld, report.ok) == (1, 0), report


def test_a_present_withheld_file_is_verified(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A local copy is verified, and a wrong one fails."""
    manifest = manifest_text([entry(FORK_PATH, FORK)])
    files = {
        "evidence/withheld.json": manifest,
        "evidence/inputs/SHA256SUMS": line(FORK, FORK_PATH),
        FORK_PATH: FORK,
    }
    make_tree(tmp_path, files)
    assert run(tmp_path).ok == 1, "a matching local copy is verified"
    (tmp_path / FORK_PATH).write_bytes(b"other")
    assert run(tmp_path).failures, "a differing local copy must fail"


def test_an_entry_in_an_excluded_corpus_is_not_imported(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Curation exclusion turns an absent target into a counted non-failure."""
    other = "evidence/gap-remediation/2026-11-14/noise-01"
    curation = {
        "schema_version": 1,
        "corpora": [{"path": other, "disposition": "excluded"}],
    }
    make_tree(
        tmp_path,
        {
            SUMS: line(DATA, f"{other}/x.bin") + line(DATA, f"{other}/y.bin"),
            "evidence/curation.json": json.dumps(curation),
        },
    )
    report = run(tmp_path)
    assert not report.failures, report.failures
    assert report.not_imported == 2, report


def test_an_entry_outside_evidence_is_external_and_listed_verbosely(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """``scripts/…`` and absolute paths are counted, not verified."""
    make_tree(
        tmp_path,
        {
            SUMS: line(DATA, "scripts/tool.py")
            + line(DATA, "/elsewhere/other.txt")
            + line(DATA, "../outside.txt")
        },
    )
    report = run(tmp_path)
    assert not report.failures, report.failures
    assert report.external == 3, report
    assert any("scripts/tool.py" in item for item in report.externals), report


def test_a_git_lfs_pointer_is_reported_with_the_remedy(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """A pointer where content belongs fails and names ``git lfs pull``."""
    pointer = b"version https://git-lfs.github.com/spec/v1\noid sha256:00\nsize 1\n"
    make_tree(tmp_path, {f"{CORPUS}/a.png": pointer, SUMS: line(DATA, "a.png")})
    report = run(tmp_path)
    assert any("git lfs pull" in f and "a.png" in f for f in report.failures), (
        report.failures
    )


def test_escaped_names_are_decoded(tmp_path: Path) -> None:
    """A leading backslash marks escaped carriage return, newline and backslash."""
    target = tmp_path / CORPUS
    target.mkdir(parents=True)
    (target / "odd\r\n\\name").write_bytes(DATA)
    text = f"\\{digest(DATA)}  odd\\r\\n\\\\name\n"
    (target / "SHA256SUMS").write_text(text, encoding="utf-8")
    report = run(tmp_path)
    assert not report.failures, report.failures
    assert report.ok == 1, report


def test_a_malformed_line_is_a_failure(tmp_path: Path, make_tree: TreeBuilder) -> None:
    """A line that is not ``<sha256>  <path>`` fails by sums file and number."""
    make_tree(tmp_path, {SUMS: "not a sums line\n"})
    report = run(tmp_path)
    assert any(SUMS in f and ":1" in f for f in report.failures), report.failures


def test_a_curation_file_marks_the_run_as_curated_only_when_present(
    tmp_path: Path, make_tree: TreeBuilder
) -> None:
    """Without a curation file nothing is excluded, so absence is a failure."""
    other = "evidence/gap-remediation/2026-11-14/noise-01"
    make_tree(tmp_path, {SUMS: line(DATA, f"{other}/x.bin")})
    assert run(tmp_path).failures, "no curation file, so the absent file is missing"


def test_verbose_lists_externals_and_conventions(
    tmp_path: Path, make_tree: TreeBuilder, capsys: pytest.CaptureFixture[str]
) -> None:
    """``--verbose`` prints each external entry and each file's convention."""
    make_tree(
        tmp_path,
        {
            f"{CORPUS}/a.txt": DATA,
            "docs/x.md": DATA,
            SUMS: line(DATA, "a.txt") + line(DATA, "docs/x.md"),
        },
    )
    code = check_sums.main(["check", "--root", str(tmp_path), "--verbose"])
    out = capsys.readouterr().out
    assert code == EXIT_OK, out
    assert f"external: {SUMS}:2: docs/x.md" in out, out
    assert f"convention dir: {SUMS}" in out, out


def test_command_line_exit_codes_and_summary(
    tmp_path: Path, make_tree: TreeBuilder, capsys: pytest.CaptureFixture[str]
) -> None:
    """Exit 0 when clean, 1 on a finding, 2 when the root is absent."""
    make_tree(tmp_path, {f"{CORPUS}/a.txt": DATA, SUMS: line(DATA, "a.txt")})
    code = check_sums.main(["check", "--root", str(tmp_path)])
    assert code == EXIT_OK, code
    assert "1 sums files, 1 entries: 1 ok" in capsys.readouterr().out, "summary"
    (tmp_path / CORPUS / "a.txt").write_bytes(b"x")
    code = check_sums.main(["check", "--root", str(tmp_path)])
    assert code == EXIT_FINDINGS, code
    code = check_sums.main(["check", "--root", str(tmp_path / "absent")])
    assert code == EXIT_MISSING, code


@pytest.mark.xfail(
    strict=True,
    reason=(
        "NEEDS-DECISION: 84 entries of export-cache-recovery-03 name package "
        "tarballs that are absent from mothra itself; no curation file is given"
    ),
)
def test_source_mode_against_the_real_mothra_checkout(
    tmp_path: Path, mothra: Path
) -> None:
    """Every sums file of the real evidence verifies, without a curation file."""
    withheld = write_mothra_manifest(tmp_path, mothra)
    report = check_sums.check(check_sums.SumsRequest(root=mothra, withheld=withheld))
    assert report.files >= 400, report.summary()
    assert not report.failures, "\n".join([*report.failures[:40], report.summary()])


def test_source_mode_with_the_generated_curation_has_no_failures(
    tmp_path: Path, mothra: Path
) -> None:
    """Corpora that curation excludes turn the 84 absent tarballs into counts."""
    withheld = write_mothra_manifest(tmp_path, mothra)
    selection = curate_select.select(
        curate_select.SelectRequest(mothra, ch.real_citing(mothra), withheld)
    )
    curation = tmp_path / "curation.json"
    curation.write_text(curate_select.selection_text(selection), encoding="utf-8")
    request = check_sums.SumsRequest(root=mothra, withheld=withheld, curation=curation)
    report = check_sums.check(request)
    assert report.files >= 400, report.summary()
    assert not report.failures, "\n".join([*report.failures[:40], report.summary()])
    assert report.not_imported >= 84, report.summary()
