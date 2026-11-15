"""The evidence corpus: the unit in which evidence is kept or left out.

A corpus is a dated directory that is kept whole so that its manifest and its
``SHA256SUMS`` stay valid. ``evidence/curation.json`` records which corpora
are included and which are not, and why.
"""

import dataclasses as dc
import json
import typing as typ

from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

CORPUS_ROOTS = ("evidence/gap-remediation", "evidence/protocol-gap-analysis")
SERVER_ROOT = "evidence/hotline-server-1.9"
PSEUDO_CORPUS = "(root)"
DATED_DEPTH = 4
SERVER_DEPTH = 3
SCHEMA_VERSION = 1
INCLUDED = "included"
EXCLUDED = "excluded"
INDENT = 2


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """One corpus and the decision about it.

    Attributes
    ----------
    path : str
        The corpus path, such as ``evidence/gap-remediation/2026-11-13/x``.
    disposition : str
        ``included`` or ``excluded``.
    files : int
        How many files it holds, withheld ones excluded.
    bytes : int
        Their total size.
    withheld : int
        How many withheld files it holds (not counted in ``files``).
    cited_by : tuple[str, ...]
        The kinds of citing file that name it.
    required_by : tuple[str, ...]
        The corpora whose manifest, plan or sums file name it.
    reason : str
        A short statement of why.
    """

    path: str
    disposition: str
    files: int
    bytes: int
    withheld: int
    cited_by: tuple[str, ...]
    required_by: tuple[str, ...]
    reason: str


def corpus_of(path: str) -> str | None:
    """Name the corpus that holds ``path``.

    The first four components identify a corpus under ``gap-remediation`` and
    ``protocol-gap-analysis``, so a loose file in a date directory is its own
    corpus. Under ``hotline-server-1.9`` the first three do, and files directly
    in that directory form the pseudo-corpus ``(root)``.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    str | None
        The corpus path, or ``None`` when the path is outside every corpus.
    """
    parts = path.split("/")
    if "/".join(parts[:2]) in CORPUS_ROOTS:
        return "/".join(parts[:DATED_DEPTH]) if len(parts) >= DATED_DEPTH else None
    if "/".join(parts[:2]) == SERVER_ROOT:
        if len(parts) == SERVER_DEPTH:
            return f"{SERVER_ROOT}/{PSEUDO_CORPUS}"
        return "/".join(parts[:SERVER_DEPTH]) if len(parts) > SERVER_DEPTH else None
    return None


def render_curation(source: dict[str, str], rule: str, corpora: list[Corpus]) -> str:
    """Render ``curation.json`` in the canonical layout.

    Parameters
    ----------
    source : dict[str, str]
        The ``repository`` and ``commit`` that the evidence was taken from.
    rule : str
        The selection rule, in one paragraph.
    corpora : list[Corpus]
        Every corpus, in any order.

    Returns
    -------
    str
        Two-space-indented JSON sorted by corpus path, ending in a newline.
    """
    items = [
        {
            "path": corpus.path,
            "disposition": corpus.disposition,
            "files": corpus.files,
            "bytes": corpus.bytes,
            "withheld": corpus.withheld,
            "cited_by": list(corpus.cited_by),
            "required_by": list(corpus.required_by),
            "reason": corpus.reason,
        }
        for corpus in sorted(corpora, key=lambda item: item.path)
    ]
    document = {
        "schema_version": SCHEMA_VERSION,
        "source": source,
        "rule": rule,
        "corpora": items,
    }
    return json.dumps(document, indent=INDENT, ensure_ascii=False) + "\n"


def load_curation(curation: Path) -> list[Corpus]:
    """Read the corpora that ``curation.json`` records.

    Parameters
    ----------
    curation : pathlib.Path
        The curation file.

    Returns
    -------
    list[Corpus]
        The corpora in file order.

    Raises
    ------
    MissingInputError
        If the file does not exist.
    """
    if not curation.is_file():
        message = f"curation file {curation} is absent"
        raise MissingInputError(message)
    document = json.loads(curation.read_text(encoding="utf-8"))
    return [
        Corpus(
            path=item["path"],
            disposition=item["disposition"],
            files=item.get("files", 0),
            bytes=item.get("bytes", 0),
            withheld=item.get("withheld", 0),
            cited_by=tuple(item.get("cited_by", ())),
            required_by=tuple(item.get("required_by", ())),
            reason=item.get("reason", ""),
        )
        for item in document["corpora"]
    ]


def load_excluded(curation: Path) -> frozenset[str]:
    """Read the corpora that ``curation.json`` excludes.

    Parameters
    ----------
    curation : pathlib.Path
        The curation file.

    Returns
    -------
    frozenset[str]
        The excluded corpus paths.
    """
    return frozenset(
        corpus.path
        for corpus in load_curation(curation)
        if corpus.disposition == EXCLUDED
    )
