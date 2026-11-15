"""The evidence corpus: the unit in which evidence is kept or left out.

A corpus is a dated directory that is kept whole so that its manifest and its
``SHA256SUMS`` stay valid. ``evidence/curation.json`` records which corpora
are included and which are not.
"""

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

    Raises
    ------
    MissingInputError
        If the file does not exist.
    """
    if not curation.is_file():
        message = f"curation file {curation} is absent"
        raise MissingInputError(message)
    document = json.loads(curation.read_text(encoding="utf-8"))
    return frozenset(
        item["path"]
        for item in document["corpora"]
        if item["disposition"] == "excluded"
    )
