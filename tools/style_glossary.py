"""Check the glossary obligation (INV-GLOSSARY) and list neighbour links.

``glossary-terms.txt`` names the terms that ``docs/glossary.md`` must define,
one per line. A line that begins ``exempt-series:`` names a capital letter that
labels something other than a work packet (a priority, a decision, a family),
so that the label scan leaves it alone. The scan reads every capital letter
followed by one to three digits as a packet label, and requires each letter
that is not exempt to be defined in the glossary's packet-label table.
"""

import dataclasses as dc
import itertools
import re
import typing as typ
from pathlib import PurePosixPath

import markdown_model as mm
from evidence_cites import Finding

if typ.TYPE_CHECKING:
    import collections.abc as cabc

RULE = "glossary"
GLOSSARY = "docs/glossary.md"
LABEL_ENTRY = "packet label"
EXEMPT_PREFIX = "exempt-series:"
LABEL = re.compile(r"(?<![\w./#-])([A-Z])\d{1,3}(?!\w|\.\d)")
LINK_TARGET = re.compile(r"\]\([^)]*\)")
SERIES_CELL = re.compile(r"^[A-Z]$")
SET_DEPTH = 3
ENTRY_LEVEL = 3


@dc.dataclass(frozen=True, slots=True)
class Terms:
    """The maintained list that the glossary is checked against.

    Attributes
    ----------
    required : tuple[str, ...]
        Each term that needs exactly one entry.
    exempt : frozenset[str]
        Series letters that do not label work packets.
    """

    required: tuple[str, ...]
    exempt: frozenset[str]


def normalize(title: str) -> str:
    """Reduce an entry title to its sorting and matching form.

    Parameters
    ----------
    title : str
        A heading's text.

    Returns
    -------
    str
        The title without backticks, in case-folded form.
    """
    return title.replace("`", "").casefold()


def parse_terms(text: str) -> Terms:
    """Read ``glossary-terms.txt``.

    Parameters
    ----------
    text : str
        The file's content; blank lines and ``#`` comments are ignored.

    Returns
    -------
    Terms
        The required terms and the exempt series letters.
    """
    required: list[str] = []
    exempt: set[str] = set()
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith(EXEMPT_PREFIX):
            exempt.add(line.removeprefix(EXEMPT_PREFIX).split()[0])
        else:
            required.append(line)
    return Terms(tuple(required), frozenset(exempt))


def _entries(text: str) -> list[tuple[str, int, str]]:
    """List the level-3 entries of the glossary with their groups.

    Parameters
    ----------
    text : str
        The glossary's source.

    Returns
    -------
    list[tuple[str, int, str]]
        Each entry's title, line and the title of its level-2 group.
    """
    group = ""
    found: list[tuple[str, int, str]] = []
    for section in mm.section_inventory(text):
        if section["level"] == ENTRY_LEVEL - 1:
            group = section["heading"]
        elif section["level"] == ENTRY_LEVEL:
            found.append((section["heading"], section["line_start"], group))
    return found


def _term_findings(entries: list[tuple[str, int, str]], terms: Terms) -> list[Finding]:
    """Find required terms that lack an entry or have several.

    Parameters
    ----------
    entries : list[tuple[str, int, str]]
        The glossary's entries.
    terms : Terms
        The maintained list.

    Returns
    -------
    list[Finding]
        One finding per term that does not have exactly one entry.
    """
    found: list[Finding] = []
    titles = [normalize(title) for title, _, _ in entries]
    for term in terms.required:
        count = titles.count(normalize(term))
        if count != 1:
            state = "has no entry" if count == 0 else f"has {count} entries"
            message = f"the term {term!r} {state}"
            found.append(Finding(GLOSSARY, 1, RULE, message, f"term {term}"))
    return found


def _order_findings(entries: list[tuple[str, int, str]]) -> list[Finding]:
    """Find entries that are out of alphabetical order within their group.

    Parameters
    ----------
    entries : list[tuple[str, int, str]]
        The glossary's entries.

    Returns
    -------
    list[Finding]
        One finding per entry that sorts before its predecessor.
    """
    found: list[Finding] = []
    for earlier, (title, line, group) in itertools.pairwise(entries):
        if earlier[2] == group and normalize(earlier[0]) > normalize(title):
            message = f"{title!r} is out of alphabetical order after {earlier[0]!r}"
            found.append(Finding(GLOSSARY, line, RULE, message, f"order {title}"))
    return found


def _anchor_findings(text: str) -> list[Finding]:
    """Find headings whose anchors repeat.

    Parameters
    ----------
    text : str
        The glossary's source.

    Returns
    -------
    list[Finding]
        One finding per heading whose anchor an earlier heading earned.
    """
    found: list[Finding] = []
    seen: set[str] = set()
    for section in mm.section_inventory(text):
        anchor = section["anchor"]
        if anchor in seen:
            message = f"the anchor #{anchor} is not unique"
            line = section["line_start"]
            found.append(Finding(GLOSSARY, line, RULE, message, f"anchor {anchor}"))
        seen.add(anchor)
    return found


def _entry_findings(text: str, terms: Terms) -> list[Finding]:
    """Check the required terms, the order and the anchors.

    Parameters
    ----------
    text : str
        The glossary's source.
    terms : Terms
        The maintained list.

    Returns
    -------
    list[Finding]
        The findings of the three checks.
    """
    entries = _entries(text)
    return [
        *_term_findings(entries, terms),
        *_order_findings(entries),
        *_anchor_findings(text),
    ]


def _defined_series(text: str) -> set[str]:
    """Read the series letters of the packet-label table.

    Parameters
    ----------
    text : str
        The glossary's source.

    Returns
    -------
    set[str]
        The single capital letters in the table's first column.
    """
    lines = text.splitlines()
    letters: set[str] = set()
    for section in mm.section_inventory(text):
        if normalize(section["heading"]) != LABEL_ENTRY:
            continue
        for first, last in mm.table_spans(text):
            if section["line_start"] < first <= section["line_end"]:
                for row in lines[first - 1 : last]:
                    cell = row.strip().strip("|").split("|")[0].strip()
                    if SERIES_CELL.match(cell):
                        letters.add(cell)
    return letters


def _label_findings(
    texts: cabc.Mapping[str, str], defined: set[str], terms: Terms
) -> list[Finding]:
    """Report each document's first use of an undefined label series.

    Parameters
    ----------
    texts : collections.abc.Mapping[str, str]
        The documents to scan, by path.
    defined : set[str]
        The letters the glossary defines.
    terms : Terms
        The maintained list, for the exempt letters.

    Returns
    -------
    list[Finding]
        One finding per document and letter.
    """
    found: list[Finding] = []
    skip = defined | terms.exempt
    for path, text in sorted(texts.items()):
        reported: set[str] = set()
        for number, line in mm.unfenced_lines(text):
            for match in LABEL.finditer(LINK_TARGET.sub("", line)):
                letter = match[1]
                if letter in skip or letter in reported:
                    continue
                reported.add(letter)
                message = (
                    f"the label series {letter} (`{match[0]}`) is not in the "
                    "glossary's packet-label table"
                )
                found.append(Finding(path, number, RULE, message, f"series {letter}"))
    return found


def _links_to(path: str, text: str, wanted: set[tuple[str, ...]]) -> bool:
    """Say whether a document links to any of the wanted files.

    Parameters
    ----------
    path : str
        The document's repository-relative path.
    text : str
        Its source.
    wanted : set[tuple[str, ...]]
        Repository-relative paths, as component tuples.

    Returns
    -------
    bool
        ``True`` when a link resolves, lexically, to one of them.
    """
    for link in mm.extract_links(text):
        target = link.target.partition("#")[0]
        external = "://" in target or target.startswith("mailto:")
        if target and not external:
            escapes, parts = mm.lexical_target(PurePosixPath(path), target)
            if not escapes and parts in wanted:
                return True
    return False


def _set_of(path: str) -> str | None:
    """Name the document set of a path.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    str | None
        The directory below ``docs/``, or ``None`` outside a set.
    """
    parts = path.split("/")
    return parts[1] if len(parts) >= SET_DEPTH and parts[0] == "docs" else None


def _overview_findings(texts: cabc.Mapping[str, str]) -> list[Finding]:
    """Check that each set overview exists and links to the glossary.

    Parameters
    ----------
    texts : collections.abc.Mapping[str, str]
        Every document, by path.

    Returns
    -------
    list[Finding]
        One finding per set whose overview is absent or does not link.
    """
    found: list[Finding] = []
    for name in sorted({s for p in texts if (s := _set_of(p))}):
        path = f"docs/{name}/README.md"
        if path not in texts:
            message = f"the set {name} has no overview"
            found.append(Finding(f"docs/{name}", 1, RULE, message, f"overview {name}"))
        elif not _links_to(path, texts[path], {("docs", "glossary.md")}):
            message = "the set overview does not link to the glossary"
            found.append(Finding(path, 1, RULE, message, "glossary link"))
    return found


def glossary_findings(
    texts: cabc.Mapping[str, str], labelled: cabc.Mapping[str, str], terms: Terms
) -> tuple[list[Finding], int]:
    """Apply the glossary obligation.

    Parameters
    ----------
    texts : collections.abc.Mapping[str, str]
        Every document that may hold an overview or the glossary, by path.
    labelled : collections.abc.Mapping[str, str]
        The documents scanned for packet labels, by path.
    terms : Terms
        The maintained list.

    Returns
    -------
    tuple[list[Finding], int]
        The findings, and how many entries the glossary holds.
    """
    glossary = texts.get(GLOSSARY)
    if glossary is None:
        return [Finding(GLOSSARY, 1, RULE, "the glossary is absent", "absent")], 0
    found = _entry_findings(glossary, terms)
    found += _label_findings(labelled, _defined_series(glossary), terms)
    found += _overview_findings(texts)
    return found, len(_entries(glossary))


def unlinked_neighbours(texts: cabc.Mapping[str, str]) -> list[str]:
    """List the set documents that link to neither their overview nor the glossary.

    Parameters
    ----------
    texts : collections.abc.Mapping[str, str]
        Every document, by path.

    Returns
    -------
    list[str]
        The paths of documents under ``docs/<set>/`` that are not overviews or
        generated indexes and link to neither.
    """
    found: list[str] = []
    for path, text in sorted(texts.items()):
        name = _set_of(path)
        if name is None or path.endswith(("/README.md", "/evidence.md")):
            continue
        wanted = {("docs", name, "README.md"), ("docs", "glossary.md")}
        if not _links_to(path, text, wanted):
            found.append(path)
    return found
