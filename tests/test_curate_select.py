"""Tests for the curation rule that selects relevant corpora (decision D22)."""

import json
import tempfile
import typing as typ
from pathlib import Path

import curate_select
import curation_helpers as ch
import pytest
from evidence_files import CitingRoot
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from withheld_helpers import write_mothra_manifest

if typ.TYPE_CHECKING:
    from evidence_corpus import Corpus


def source(tmp_path: Path) -> Path:
    """Create the synthetic source tree.

    Returns
    -------
    pathlib.Path
        Its root.
    """
    root = tmp_path / "source"
    ch.write_tree(root, ch.SOURCE)
    return root


def cite(tmp_path: Path, text: str, kind: str = "document") -> CitingRoot:
    """Write a citing file holding ``text``.

    Returns
    -------
    CitingRoot
        The file, labelled with ``kind``.
    """
    target = tmp_path / f"cite-{kind}-{len(list(tmp_path.glob('cite-*')))}.md"
    target.write_text(text, encoding="utf-8")
    return CitingRoot(kind, target)


def run(tmp_path: Path, *citing: CitingRoot) -> dict[str, Corpus]:
    """Run ``select`` over the synthetic source.

    Returns
    -------
    dict[str, Corpus]
        The corpora by path.
    """
    root = tmp_path / "source"
    if not root.exists():
        source(tmp_path)
    request = curate_select.SelectRequest(
        source_root=root,
        citing=citing,
        withheld=ch.write_withheld(tmp_path),
        commit="c0ffee",
    )
    return {c.path: c for c in curate_select.select(request).corpora}


def included(corpora: dict[str, Corpus]) -> set[str]:
    """Return the paths of the included corpora.

    Returns
    -------
    set[str]
        The paths.
    """
    return {p for p, c in corpora.items() if c.disposition == "included"}


def test_a_direct_citation_selects_its_corpus_and_records_who_cited_it(
    tmp_path: Path,
) -> None:
    """Only the cited corpus is relevant, and the citing kinds are recorded."""
    corpora = run(
        tmp_path,
        cite(tmp_path, f"see {ch.PM2}/data.json."),
        cite(tmp_path, f"also {ch.PM2}/", "register"),
    )
    assert corpora[ch.PM2].disposition == "included", corpora[ch.PM2]
    assert corpora[ch.PM2].cited_by == ("document", "register"), corpora[ch.PM2]
    assert corpora[ch.PM1].disposition == "excluded", corpora[ch.PM1]
    assert corpora[ch.PM1].cited_by == (), corpora[ch.PM1]


def test_a_manifest_of_a_relevant_corpus_pulls_in_what_it_cites(
    tmp_path: Path,
) -> None:
    """Closure: the manifest names revision 70, so it is required by PM1."""
    corpora = run(tmp_path, cite(tmp_path, f"{ch.PM1}/data.bin"))
    assert corpora[ch.REV70].disposition == "included", corpora[ch.REV70]
    assert corpora[ch.REV70].required_by == (ch.PM1,), corpora[ch.REV70]
    assert corpora[ch.REV70].cited_by == (), corpora[ch.REV70]
    assert corpora[ch.NOISE].disposition == "excluded", corpora[ch.NOISE]


def test_only_manifest_like_files_extend_the_closure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A payload file that names a corpus does not pull it in."""
    root = source(tmp_path)
    (root / ch.PM2 / "data.json").write_text(f'"{ch.NOISE}/x.txt"', encoding="utf-8")
    corpora = run(tmp_path, cite(tmp_path, f"{ch.PM2}/data.json"))
    assert corpora[ch.NOISE].disposition == "excluded", corpora[ch.NOISE]
    monkeypatch.setattr("curate_select.MANIFEST_LIMIT", 1)
    corpora = run(tmp_path, cite(tmp_path, f"{ch.PM1}/data.bin"))
    assert corpora[ch.REV70].disposition == "excluded", "a large manifest is skipped"


@pytest.mark.parametrize(
    "text",
    [
        "evidence/",
        "evidence/gap-remediation/",
        "evidence/gap-remediation/2026-11-13",
        "evidence/gap-remediation/2026-11-13/",
        "evidence/protocol-gap-analysis/2026-11-14/*",
        "evidence/gap-remediation/<date>/native-pm-01",
    ],
)
def test_a_bare_date_directory_or_evidence_selects_nothing(
    tmp_path: Path, text: str
) -> None:
    """Only a path inside a corpus selects it."""
    corpora = run(tmp_path, cite(tmp_path, f"see {text} for details"))
    assert not included(corpora), included(corpora)


def test_loose_files_and_the_server_pseudo_corpus(tmp_path: Path) -> None:
    """A loose file is its own corpus; root files form ``(root)``."""
    claims = "evidence/hotline-server-1.9/claims.json"
    corpora = run(tmp_path, cite(tmp_path, f"{ch.LOOSE} and {claims}"))
    assert included(corpora) == {ch.LOOSE, ch.PSEUDO}, included(corpora)
    assert ch.QUERIES in corpora, "queries is its own corpus"
    assert corpora[ch.QUERIES].disposition == "excluded", corpora[ch.QUERIES]


def test_withheld_files_are_counted_apart(tmp_path: Path) -> None:
    """The fork is neither a file nor bytes of its corpus; it is withheld."""
    corpora = run(tmp_path, cite(tmp_path, f"{ch.INPUTS}/notes.txt"))
    inputs = corpora[ch.INPUTS]
    assert (inputs.files, inputs.bytes, inputs.withheld) == (1, 6, 1), inputs


def test_another_projects_evidence_is_not_a_corpus(tmp_path: Path) -> None:
    """``runtime-network`` is never listed, even when cited."""
    corpora = run(tmp_path, cite(tmp_path, "evidence/runtime-network/2026-11-13/x.txt"))
    assert not any("runtime-network" in path for path in corpora), sorted(corpora)


def test_counts_and_sorted_canonical_output(tmp_path: Path) -> None:
    """The rendered file is canonical JSON sorted by path with the source."""
    request = curate_select.SelectRequest(
        source_root=source(tmp_path),
        citing=(cite(tmp_path, f"{ch.PM1}/data.bin"),),
        withheld=ch.write_withheld(tmp_path),
        commit="c0ffee",
    )
    text = curate_select.selection_text(curate_select.select(request))
    document = json.loads(text)
    paths = [item["path"] for item in document["corpora"]]
    assert paths == sorted(paths), paths
    expected = {"repository": "leynos/mothra", "commit": "c0ffee"}
    assert document["source"] == expected, document["source"]
    pm1 = next(i for i in document["corpora"] if i["path"] == ch.PM1)
    sizes = [len(ch.as_bytes(v)) for k, v in ch.SOURCE.items() if k.startswith(ch.PM1)]
    assert (pm1["files"], pm1["bytes"]) == (3, sum(sizes)), pm1
    assert text == json.dumps(document, indent=2, ensure_ascii=False) + "\n", (
        "canonical"
    )


def test_a_citing_directory_is_scanned_recursively(tmp_path: Path) -> None:
    """Every file below a directory root is scanned, and carries its kind."""
    directory = tmp_path / "scripts"
    (directory / "sub").mkdir(parents=True)
    (directory / "sub" / "x.py").write_text(f'"{ch.PM2}/data.json"', encoding="utf-8")
    corpora = run(tmp_path, CitingRoot("script", directory))
    assert corpora[ch.PM2].cited_by == ("script",), corpora[ch.PM2]


CORPUS_CITES = [
    f"{ch.PM1}/a",
    f"{ch.PM2}/a",
    f"{ch.NOISE}/a",
    f"{ch.REV70}/a",
    ch.LOOSE,
    "evidence/hotline-server-1.9/claims.json",
]


@settings(
    max_examples=25,
    deadline=None,
    suppress_health_check=[HealthCheck.function_scoped_fixture],
)
@given(
    first=st.lists(st.sampled_from(CORPUS_CITES), max_size=4),
    extra=st.lists(st.sampled_from(CORPUS_CITES), max_size=4),
)
def test_select_is_idempotent_and_monotone(first: list[str], extra: list[str]) -> None:
    """The same input gives the same output, and more citing files add corpora."""
    with tempfile.TemporaryDirectory() as scratch:
        tmp_path = Path(scratch)
        base = cite(tmp_path, " ".join(first))
        more = cite(tmp_path, " ".join(extra), "ledger")
        once = run(tmp_path, base)
        assert run(tmp_path, base) == once, "select must be idempotent"
        wider = run(tmp_path, base, more)
        assert included(once) <= included(wider), "adding a citing file removed one"


def test_real_selection_over_the_mothra_checkout(tmp_path: Path, mothra: Path) -> None:
    """The rule keeps at least 180 corpora and drops the known noise."""
    request = curate_select.SelectRequest(
        source_root=mothra,
        citing=ch.real_citing(mothra),
        withheld=write_mothra_manifest(tmp_path, mothra),
    )
    corpora = curate_select.select(request).corpora
    kept = [c for c in corpora if c.disposition == "included"]
    dropped = [c for c in corpora if c.disposition == "excluded"]
    totals = (
        f"{len(kept)} included ({sum(c.files for c in kept)} files), "
        f"{len(dropped)} excluded ({sum(c.files for c in dropped)} files)"
    )
    names = {c.path for c in dropped}
    assert len(kept) >= 180, totals
    assert "evidence/gap-remediation/2026-11-14/export-cache-cleanup-01" in names, (
        totals
    )
    assert "evidence/protocol-gap-analysis/2026-11-14/revision-70" in names, totals
