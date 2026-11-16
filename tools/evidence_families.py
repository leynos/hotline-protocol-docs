"""Read the corpus families and the remaining-work ledger from their documents.

The recreation guide states how each family of corpora is recreated, in a table
(Table 5 of ``recreating-evidence.md``) that lists corpora by short name and by
range. This module reads that table under a fixed convention:

* A row whose first cell begins ``F<number>`` (and an optional letter) is a
  family; its second cell is the kind and its fourth cell lists the corpora.
* Every code span of the fourth cell names a corpus by its last path component.
  A span of the form ``evidence/<root>/`` sets the scope for the spans after
  it, so ``inputs`` under ``hotline-server-1.9`` is not ``inputs`` under a dated
  directory. A date label such as ``11-12:`` is ignored.
* ``A`` to ``B`` between two spans covers every name from ``A`` to ``B`` that
  differs only in a trailing number, such as ``batch-01`` to ``batch-17``.
* A cell that links to ``#families`` also covers every corpus named in the
  second cell of Table 3 (the table whose header begins ``Included corpora``).
* Corpora listed in ``evidence/local-corpora.json`` form the family ``local``.

The ledger of remaining work is read from the first table of its document.
"""

import dataclasses as dc
import json
import re
import typing as typ

import markdown_model as mm
from evidence_cites import GAP_ID

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

FAMILY_ROW = re.compile(r"^F\d+[a-z]?\b")
SPAN = re.compile(r"`([^`]+)`")
RANGE = re.compile(r"`([^`]+)`\s+to\s+`([^`]+)`")
TRAILING_NUMBER = re.compile(r"^(.*?)(\d+)$")
TABLE_THREE_LINK = "(#families)"
SCOPED = re.compile(r"^evidence/([\w.-]+)/$")
FAMILY_COLUMNS = 4
LOCAL = "local"
LOCAL_KIND = "Local audit revision"


@dc.dataclass(frozen=True, slots=True)
class Family:
    """One row of the guide's table of corpus families.

    Attributes
    ----------
    label : str
        The family label, for example ``F10 Native capture``.
    kind : str
        The kind column.
    """

    label: str
    kind: str


@dc.dataclass(slots=True)
class FamilyTable:
    """The corpora that the guide covers, with the family of each.

    Attributes
    ----------
    entries : dict[tuple[str | None, str], Family]
        Family by ``(scope, corpus name)``; the scope is the evidence root
        (``hotline-server-1.9``) or ``None`` for any other root.
    """

    entries: dict[tuple[str | None, str], Family] = dc.field(default_factory=dict)

    def lookup(self, corpus: str) -> Family | None:
        """Find the family of a corpus path.

        Parameters
        ----------
        corpus : str
            A corpus path such as ``evidence/gap-remediation/2026-11-13/x``.

        Returns
        -------
        Family | None
            The family, or ``None`` when the guide does not cover the corpus.
        """
        parts = corpus.split("/")
        scope = parts[1] if parts[1:2] == ["hotline-server-1.9"] else None
        return self.entries.get((scope, parts[-1]))


def _cells(line: str) -> list[str]:
    """Split a table row into stripped cells.

    Parameters
    ----------
    line : str
        A row that starts with ``|``.

    Returns
    -------
    list[str]
        The cells.
    """
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _expand(first: str, last: str) -> list[str]:
    """List the names from ``first`` to ``last`` that differ in a final number.

    Parameters
    ----------
    first : str
        The first name, such as ``batch-01``.
    last : str
        The last name, such as ``batch-17``.

    Returns
    -------
    list[str]
        Every name in the range, or the two ends when they do not form one.
    """
    low, high = TRAILING_NUMBER.match(first), TRAILING_NUMBER.match(last)
    if low is None or high is None:
        return [first, last]
    if low[1] != high[1]:
        return [first, last]
    width = len(low[2])
    return [
        f"{low[1]}{number:0{width}d}" for number in range(int(low[2]), int(high[2]) + 1)
    ]


def corpus_names(cell: str) -> list[tuple[str | None, str]]:
    """List the ``(scope, name)`` pairs that a corpora cell names.

    Parameters
    ----------
    cell : str
        The cell text.

    Returns
    -------
    list[tuple[str | None, str]]
        Each corpus name with its scope.
    """
    ranged = {
        m[1]: _expand(m[1].rsplit("/", 1)[-1], m[2].rsplit("/", 1)[-1])
        for m in RANGE.finditer(cell)
    }
    ends = {m[2] for m in RANGE.finditer(cell)}
    scope: str | None = None
    names: list[tuple[str | None, str]] = []
    for span in (m[1] for m in SPAN.finditer(cell)):
        container = SCOPED.match(span)
        if container:
            scope = container[1]
        elif span not in ends:
            last = span.rstrip("/").rsplit("/", 1)[-1]
            names.extend((scope, name) for name in ranged.get(span, [last]))
    return names


def _table_rows(text: str) -> cabc.Iterator[list[str]]:
    """Yield the cells of every table row outside code fences.

    Parameters
    ----------
    text : str
        The Markdown source.

    Yields
    ------
    list[str]
        The cells of one row.
    """
    for _, line in mm.unfenced_lines(text):
        if line.lstrip().startswith("|"):
            yield _cells(line)


def parse_families(guide: str, local: cabc.Iterable[str] = ()) -> FamilyTable:
    """Read the corpus-family table of the recreation guide.

    Parameters
    ----------
    guide : str
        The guide's Markdown source.
    local : collections.abc.Iterable[str]
        Paths of the corpora listed in ``evidence/local-corpora.json``.

    Returns
    -------
    FamilyTable
        The families and the corpus names that each covers.
    """
    native: list[tuple[str | None, str]] = []
    families: list[tuple[Family, list[tuple[str | None, str]], bool]] = []
    in_native_table = False
    for row in _table_rows(guide):
        if row[0] == "Family":
            in_native_table = row[1].startswith("Included corpora")
        elif in_native_table and not row[0].startswith("-"):
            native.extend(corpus_names(row[1]))
        elif len(row) >= FAMILY_COLUMNS and FAMILY_ROW.match(row[0]):
            families.append((
                Family(row[0], row[1]),
                corpus_names(row[3]),
                TABLE_THREE_LINK in row[3],
            ))
    table = FamilyTable()
    for family, names, inherits in families:
        covered = [*names, *(native if inherits else [])]
        table.entries.update(dict.fromkeys(covered, family))
    for path in local:
        table.entries[None, path.rsplit("/", 1)[-1]] = Family(LOCAL, LOCAL_KIND)
    return table


def load_local(path: Path) -> list[str]:
    """Read the corpus paths of ``evidence/local-corpora.json``.

    Parameters
    ----------
    path : pathlib.Path
        The file; a missing file lists nothing.

    Returns
    -------
    list[str]
        The corpus paths.
    """
    if not path.is_file():
        return []
    data = json.loads(path.read_text(encoding="utf-8"))
    return [entry["path"] for entry in data.get("corpora", [])]


def ledger_rows(text: str) -> list[tuple[int, list[str]]]:
    """Read the gap identifiers in the first cell of each row of the first table.

    Parameters
    ----------
    text : str
        The Markdown source of the remaining-work ledger.

    Returns
    -------
    list[tuple[int, list[str]]]
        The line and the identifiers of each data row of the first table.
    """
    rows: list[tuple[int, list[str]]] = []
    started = False
    for number, line in mm.unfenced_lines(text):
        if not line.lstrip().startswith("|"):
            if started:
                break
            continue
        first = _cells(line)[0]
        if not started:
            started = True
            continue
        if not first.strip("-: "):
            continue
        rows.append((number, [f"GAP-{m[1]}" for m in GAP_ID.finditer(first)]))
    return rows
