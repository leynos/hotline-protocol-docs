"""Check that every document under ``docs/`` can be reached from the indexes.

Every Markdown document under ``docs/`` appears exactly once in
``docs/contents.md``, as the link that opens a list item. A document inside a
set directory, ``docs/<set>/``, also appears exactly once in the first cell of
a table row of that set's overview, ``docs/<set>/README.md``. Links elsewhere,
in a description or in a later cell, are references and are not counted.
Execution plans, the contents page, the set
overviews and any explicitly exempt working records are not themselves
required to be listed.
"""

import collections as col
import urllib.parse as urlparse
from pathlib import Path

import markdown_model as mm
from repo_files import repo_files

DOCS = "docs"
CONTENTS = "docs/contents.md"
EXECPLANS = "docs/execplans/"
OVERVIEW = "README.md"
SET_DEPTH = 3
EXTERNAL = ("http://", "https://", "mailto:")
LIST_ITEM_LINK = "- ["


def _resolved(source: Path, target: str) -> str | None:
    """Resolve a link target to a repository-relative POSIX path.

    Parameters
    ----------
    source : pathlib.Path
        The linking document, relative to the root.
    target : str
        The link target as written.

    Returns
    -------
    str | None
        The path, or ``None`` for external, same-file and escaping links.
    """
    path = urlparse.unquote(target).partition("#")[0]
    if not path or target.startswith(EXTERNAL):
        return None
    escapes, parts = mm.lexical_target(source, path)
    return "/".join(parts) if escapes == 0 else None


def _listing_part(line: str, *, tables_only: bool) -> str:
    """Return the part of an index line that lists a document.

    Parameters
    ----------
    line : str
        One line of an index document.
    tables_only : bool
        ``True`` for a set overview, ``False`` for the contents page.

    Returns
    -------
    str
        The first cell of a table row, or the link that opens a list item;
        empty when the line lists nothing.
    """
    stripped = line.lstrip()
    if tables_only:
        cells = stripped.split("|")
        return cells[1] if stripped.startswith("|") and len(cells) > 1 else ""
    if not stripped.startswith(LIST_ITEM_LINK):
        return ""
    end = stripped.find(")")
    return stripped[: end + 1]


def _targets(root: Path, source: Path, *, tables_only: bool) -> col.Counter[str]:
    """Count the documents that ``source`` links to.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    source : pathlib.Path
        The index document, relative to the root.
    tables_only : bool
        Count the links in the first cell of each table row; otherwise count
        the link that opens each list item.

    Returns
    -------
    collections.Counter[str]
        Link count per resolved repository-relative path.
    """
    text = (root / source).read_text(encoding="utf-8")
    counts: col.Counter[str] = col.Counter()
    for _, line in mm.unfenced_lines(text):
        for link in mm.extract_links(_listing_part(line, tables_only=tables_only)):
            target = _resolved(source, link.target)
            if target is not None:
                counts[target] += 1
    return counts


def _judge(name: str, index: str, counts: col.Counter[str]) -> list[str]:
    """Judge how often an index lists a document.

    Parameters
    ----------
    name : str
        The document's repository-relative path.
    index : str
        The index's path, for the message.
    counts : collections.Counter[str]
        Link counts of that index.

    Returns
    -------
    list[str]
        Zero or one failure message.
    """
    found = counts[name]
    if found == 1:
        return []
    kind = "is not listed in" if found == 0 else f"is listed {found} times in"
    return [f"{name}: {kind} {index}"]


def _overview_of(path: Path) -> str | None:
    """Name the overview that must list a document, if there is one.

    Parameters
    ----------
    path : pathlib.Path
        A document below ``docs/``, relative to the root.

    Returns
    -------
    str | None
        The set overview's path, or ``None`` for a document outside any set.
    """
    if len(path.parts) < SET_DEPTH:
        return None
    return f"{DOCS}/{path.parts[1]}/{OVERVIEW}"


def _needs_listing(path: Path, exempt: frozenset[str]) -> bool:
    """Say whether a document must appear in the indexes.

    Parameters
    ----------
    path : pathlib.Path
        A Markdown path relative to the root.
    exempt : frozenset[str]
        Paths of working records that need not be listed.

    Returns
    -------
    bool
        ``False`` for anything outside ``docs/``, execution plans, the contents
        page, set overviews and exempt records.
    """
    name = path.as_posix()
    if path.parts[0] != DOCS or name.startswith(EXECPLANS):
        return False
    if name in exempt:
        return False
    is_overview = len(path.parts) == SET_DEPTH and path.name == OVERVIEW
    return name != CONTENTS and not is_overview


def check_reach(root: Path, *, exempt: frozenset[str] = frozenset()) -> list[str]:
    """Find documents that are missing from, or repeated in, the indexes.

    Parameters
    ----------
    root : pathlib.Path
        The repository root.
    exempt : frozenset[str]
        Repository-relative paths of working records that need not be listed.

    Returns
    -------
    list[str]
        One message per violation.
    """
    contents = _targets(root, Path(CONTENTS), tables_only=False)
    overviews: dict[str, col.Counter[str]] = {}
    failures: list[str] = []
    for path in repo_files(root, ".md"):
        if not _needs_listing(path, exempt):
            continue
        failures += _judge(path.as_posix(), CONTENTS, contents)
        overview = _overview_of(path)
        if overview is None:
            continue
        if overview not in overviews:
            present = (root / overview).is_file()
            overviews[overview] = (
                _targets(root, Path(overview), tables_only=True)
                if present
                else col.Counter()
            )
        failures += _judge(path.as_posix(), overview, overviews[overview])
    return failures
