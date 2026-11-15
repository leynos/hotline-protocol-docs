"""Decide which evidence corpora are relevant (decision D22).

A corpus is relevant when a protocol document, the gap register, the validity
ledger, a script or a recipe cites a path inside it, or when the manifest,
plan or sums file of a relevant corpus does.
"""

import collections as col
import dataclasses as dc
import re
from pathlib import Path

from evidence_corpus import EXCLUDED, INCLUDED, Corpus, corpus_of, render_curation
from evidence_files import CitingRoot, cited_paths, citing_files, list_files
from git_lossless import GitCommandError, git_text
from withheld_model import MANIFEST_RELATIVE, load_manifest

MANIFEST_LIMIT = 3_000_000
MANIFEST_LIKE = re.compile(
    r"manifest|plan|verification|review|README|SHA256SUMS|index", re.IGNORECASE
)
RULE = (
    "A corpus is a dated directory kept whole. It is included when a protocol "
    "document, the gap register, the validity ledger, a capture or verifier "
    "script, or a retained check recipe cites a path equal to or inside it, or "
    "when the manifest, plan, verification, review, README, index or sums file "
    "(at most 3 MB) of an included corpus cites a path inside it. A citation of "
    "evidence/ or of a bare date directory selects nothing. Every other corpus is "
    "excluded. Withheld files are listed in withheld.json and counted apart."
)
REPOSITORY = "leynos/mothra"


@dc.dataclass(frozen=True, slots=True)
class SelectRequest:
    """What ``select`` decides from.

    Attributes
    ----------
    source_root : pathlib.Path
        A tree that contains ``evidence/``.
    citing : tuple[CitingRoot, ...]
        The files and directories whose citations select corpora.
    withheld : pathlib.Path | None
        The withheld manifest, whose paths are never counted.
    commit : str
        The source commit to record; defaults to the checkout's ``HEAD``.
    """

    source_root: Path
    citing: tuple[CitingRoot, ...]
    withheld: Path | None = None
    commit: str = ""


@dc.dataclass(frozen=True, slots=True)
class Selection:
    """The outcome of ``select``.

    Attributes
    ----------
    corpora : list[Corpus]
        Every corpus of the source, with its disposition.
    source : dict[str, str]
        The repository and commit that were read.
    """

    corpora: list[Corpus]
    source: dict[str, str]


@dc.dataclass(slots=True)
class Stats:
    """The files of one corpus.

    Attributes
    ----------
    names : list[str]
        Its files that are not withheld.
    bytes : int
        Their total size.
    withheld : int
        How many withheld files it holds.
    """

    names: list[str] = dc.field(default_factory=list)
    bytes: int = 0
    withheld: int = 0


def withheld_paths(explicit: Path | None, root: Path) -> frozenset[str]:
    """Read the withheld paths from ``explicit`` or the default manifest.

    Returns
    -------
    frozenset[str]
        The paths; empty when no manifest is given and none exists.
    """
    manifest = explicit or root / MANIFEST_RELATIVE
    if explicit is None and not manifest.is_file():
        return frozenset()
    return load_manifest(manifest).paths


def _tally(root: Path, withheld: frozenset[str]) -> dict[str, Stats]:
    """Group the source's files by corpus.

    Returns
    -------
    dict[str, Stats]
        The corpus path to its files, in source order.
    """
    corpora: dict[str, Stats] = {}
    for name in list_files(root):
        corpus = corpus_of(name)
        if corpus is None:
            continue
        stats = corpora.setdefault(corpus, Stats())
        if name in withheld:
            stats.withheld += 1
        else:
            stats.names.append(name)
            stats.bytes += (root / name).stat().st_size
    return corpora


def _corpus_cited(path: str, known: dict[str, Stats]) -> str | None:
    """Name the corpus that a cited path selects.

    Returns
    -------
    str | None
        The corpus, or ``None`` when the path is not inside a known corpus.
    """
    corpus = path if path in known else corpus_of(path)
    return corpus if corpus in known else None


def _cited_by(
    citing: tuple[CitingRoot, ...], known: dict[str, Stats]
) -> dict[str, set[str]]:
    """Find which kinds of citing file name each corpus.

    Returns
    -------
    dict[str, set[str]]
        The corpus path to the kinds that cite it.
    """
    found: dict[str, set[str]] = col.defaultdict(set)
    for root in citing:
        for file in citing_files(root):
            for path in cited_paths(file.read_bytes()):
                corpus = _corpus_cited(path, known)
                if corpus:
                    found[corpus].add(root.kind)
    return found


def _required_by(
    root: Path, known: dict[str, Stats], relevant: set[str]
) -> dict[str, set[str]]:
    """Extend ``relevant`` through the manifests of relevant corpora.

    Parameters
    ----------
    root : pathlib.Path
        The source checkout.
    known : dict[str, Stats]
        Every corpus.
    relevant : set[str]
        The relevant corpora; this set grows to its closure.

    Returns
    -------
    dict[str, set[str]]
        Each corpus to the relevant corpora whose manifests cite it.
    """
    required: dict[str, set[str]] = col.defaultdict(set)
    queue = sorted(relevant)
    while queue:
        current = queue.pop(0)
        for name in known[current].names:
            target = root / name
            if not MANIFEST_LIKE.search(Path(name).name):
                continue
            if target.stat().st_size > MANIFEST_LIMIT:
                continue
            for path in cited_paths(target.read_bytes()):
                corpus = _corpus_cited(path, known)
                if corpus and corpus != current:
                    required[corpus].add(current)
                    if corpus not in relevant:
                        relevant.add(corpus)
                        queue.append(corpus)
    return required


def _reason(kinds: set[str], needed: set[str]) -> str:
    """Say why a corpus is included or excluded.

    Returns
    -------
    str
        A short statement.
    """
    parts = []
    if kinds:
        parts.append("cited by " + ", ".join(sorted(kinds)))
    if needed:
        parts.append(f"required by {len(needed)} corpora")
    return "; ".join(parts) or "not cited by any citing file or relevant manifest"


def select(request: SelectRequest) -> Selection:
    """Decide which corpora are relevant.

    Parameters
    ----------
    request : SelectRequest
        The source and the citing roots.

    Returns
    -------
    Selection
        Every corpus with its disposition and reason.
    """
    root = request.source_root
    known = _tally(root, withheld_paths(request.withheld, root))
    cited = _cited_by(request.citing, known)
    relevant = set(cited)
    required = _required_by(root, known, relevant)
    corpora = [
        Corpus(
            path=path,
            disposition=INCLUDED if path in relevant else EXCLUDED,
            files=len(stats.names),
            bytes=stats.bytes,
            withheld=stats.withheld,
            cited_by=tuple(sorted(cited.get(path, ()))),
            required_by=tuple(sorted(required.get(path, ()))),
            reason=_reason(cited.get(path, set()), required.get(path, set())),
        )
        for path, stats in known.items()
    ]
    return Selection(corpora, {"repository": REPOSITORY, "commit": _commit(request)})


def _commit(request: SelectRequest) -> str:
    """Return the recorded commit: the one given, else the checkout's ``HEAD``.

    Returns
    -------
    str
        The commit, or an empty string when the source is not a repository.
    """
    if request.commit:
        return request.commit
    try:
        return git_text(request.source_root, "rev-parse", "HEAD").strip()
    except GitCommandError:
        return ""


def selection_text(selection: Selection) -> str:
    """Render a selection as ``curation.json``.

    Parameters
    ----------
    selection : Selection
        The selection.

    Returns
    -------
    str
        The canonical JSON text.
    """
    return render_curation(selection.source, RULE, selection.corpora)
