"""The rules of ``check_evidence`` other than the status rule and the indexes.

Each rule takes already-read data and returns findings, so that the tests can
drive it without a repository on disk.
"""

import dataclasses as dc
import re
import typing as typ

import markdown_model as mm
from evidence_cites import Finding, Occurrence

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from evidence_cites import DocCites
    from evidence_families import FamilyTable

# A script named in a code span or link of the recreation guide, with or without
# its directory. Corpus verifiers keep their own names inside the corpus.
GUIDE_SCRIPT = re.compile(
    r"^(?:\.\./)*(?:(?:scripts|tools)/)?[\w.-]+\.(?:py|sh|py\.txt)$|^verify[\w-]*\.txt$"
)


@dc.dataclass(frozen=True, slots=True)
class Known:
    """The identifiers and files that a repository defines.

    Attributes
    ----------
    ledger : frozenset[str]
        Ledger identifiers defined in ``claims.json``.
    gaps : dict[str, str]
        Register status by gap identifier.
    """

    ledger: frozenset[str]
    gaps: dict[str, str]


def identifier_findings(cites: DocCites, known: Known) -> list[Finding]:
    """Find cited identifiers that nothing defines.

    Parameters
    ----------
    cites : DocCites
        One document's citations.
    known : Known
        The defined identifiers.

    Returns
    -------
    list[Finding]
        One finding per undefined citation.
    """
    found = [
        Finding(
            cites.path,
            o.line,
            "ledger-id",
            f"{o.value} is not defined in claims.json",
            o.value,
        )
        for o in cites.ledger
        if o.value not in known.ledger
    ]
    found += [
        Finding(
            cites.path,
            o.line,
            "gap-id",
            f"{o.value} is not in the gap register",
            o.value,
        )
        for o in cites.gaps
        if o.value not in known.gaps
    ]
    return found


def script_findings(cites: DocCites, root: Path) -> list[Finding]:
    """Find cited scripts that do not exist.

    Parameters
    ----------
    cites : DocCites
        One document's citations.
    root : pathlib.Path
        The repository root.

    Returns
    -------
    list[Finding]
        One finding per citation of a missing path.
    """
    return [
        Finding(cites.path, o.line, "script", f"{o.value} does not exist", o.value)
        for o in cites.scripts
        if not (root / o.value).exists()
    ]


def ledger_table_findings(
    path: str, rows: list[tuple[int, list[str]]], gaps: cabc.Mapping[str, str]
) -> list[Finding]:
    """Check the remaining-work ledger against the register (decision D26).

    Every gap that is not Resolved appears exactly once in the first cell of a
    row, and no Resolved gap appears.

    Parameters
    ----------
    path : str
        The ledger document's path.
    rows : list[tuple[int, list[str]]]
        The line and the gap identifiers of each row.
    gaps : collections.abc.Mapping[str, str]
        Register status by gap identifier.

    Returns
    -------
    list[Finding]
        One finding per missing, repeated, Resolved or unknown gap.
    """
    seen: dict[str, int] = {}
    found: list[Finding] = []
    for line, identifiers in rows:
        for gap in identifiers:
            status = gaps.get(gap)
            problem = None
            if status is None:
                problem = f"{gap} is not in the gap register"
            elif status == "Resolved":
                problem = f"{gap} is Resolved and must not be listed"
            elif gap in seen:
                problem = f"{gap} is listed again (first on line {seen[gap]})"
            seen.setdefault(gap, line)
            if problem:
                found.append(Finding(path, line, "ledger-table", problem, gap))
    first = rows[0][0] if rows else 1
    found += [
        Finding(
            path, first, "ledger-table", f"{gap} is {status} and is not listed", gap
        )
        for gap, status in sorted(gaps.items())
        if status != "Resolved" and gap not in seen
    ]
    return found


def family_findings(
    docs: cabc.Iterable[DocCites], families: FamilyTable
) -> tuple[list[Finding], set[str]]:
    """Find cited corpora that no family of the recreation guide covers.

    Parameters
    ----------
    docs : collections.abc.Iterable[DocCites]
        The citing documents.
    families : FamilyTable
        The guide's families.

    Returns
    -------
    tuple[list[Finding], set[str]]
        One finding per uncovered corpus, at its first citation, and the set of
        every corpus that is cited.
    """
    first: dict[str, tuple[str, Occurrence]] = {}
    for cites in docs:
        for occurrence in cites.corpora:
            first.setdefault(occurrence.value, (cites.path, occurrence))
    found = [
        Finding(
            path,
            occurrence.line,
            "family",
            f"{corpus} is not covered by a family in the recreation guide",
            corpus,
        )
        for corpus, (path, occurrence) in sorted(first.items())
        if families.lookup(corpus) is None
    ]
    return found, set(first)


def guide_tokens(text: str) -> list[tuple[int, str]]:
    """List the script-like words in the code spans and links of the guide.

    Parameters
    ----------
    text : str
        The guide's Markdown source.

    Returns
    -------
    list[tuple[int, str]]
        The line and the word, without any ``../`` prefix.
    """
    found: list[tuple[int, str]] = []
    for number, line in mm.unfenced_lines(text):
        pieces = [m[0].strip("`") for m in mm.CODE_SPAN.finditer(line)]
        pieces += [m[1] for m in mm.INLINE_LINK.finditer(line)]
        found.extend(
            (number, word.removeprefix("../") if word.startswith("../") else word)
            for piece in pieces
            for word in piece.split()
            if GUIDE_SCRIPT.match(word.partition("#")[0])
        )
    return found


def guide_findings(
    path: str, text: str, root: Path, retained: cabc.Collection[str]
) -> list[Finding]:
    """Find scripts that the recreation guide names and the repository lacks.

    A name with ``scripts/`` or ``tools/`` must exist at that path. A bare name
    must exist in ``scripts/`` or ``tools/``, or be the name of a file inside a
    retained corpus (a verifier that a corpus carries for itself).

    Parameters
    ----------
    path : str
        The guide's path.
    text : str
        Its Markdown source.
    root : pathlib.Path
        The repository root.
    retained : collections.abc.Collection[str]
        The file names found under ``evidence/``.

    Returns
    -------
    list[Finding]
        One finding per missing script.
    """
    found: list[Finding] = []
    for line, raw in guide_tokens(text):
        word = raw.partition("#")[0]
        while word.startswith("../"):
            word = word[3:]
        if "/" in word:
            present = (root / word).exists()
        else:
            present = (
                (root / "scripts" / word).exists()
                or (root / "tools" / word).exists()
                or word in retained
            )
        if not present:
            found.append(
                Finding(path, line, "guide-script", f"{word} does not exist", word)
            )
    return found
