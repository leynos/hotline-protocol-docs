"""Rewrite relative Markdown links when documents move (obligation INV-MOVE).

A move map sends the old repository path of each moved file to its new path.
:func:`rewrite_link` keeps one invariant: resolving the rewritten link from the
linking document's new location yields the mapped counterpart of what the old
link resolved to from its old location. Fragments, titles, link style and the
text around each link are never touched, and a link that already holds
(``./x.md`` after a sibling move, say) is returned exactly as written.

Links inside fenced code and inline code spans are never rewritten; the same
fence and link rules as the link checker apply, through :mod:`markdown_model`.
This module belongs to the one-off relocation and is deleted with it.
"""

import dataclasses as dc
import re
import typing as typ
import urllib.parse as urlparse
from pathlib import PurePosixPath

import markdown_model as mm

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Moves = cabc.Mapping[PurePosixPath, PurePosixPath]
type Resolution = tuple[int, tuple[str, ...]]

SCHEME = re.compile(r"^[A-Za-z][A-Za-z0-9+.-]*:")


@dc.dataclass(frozen=True, slots=True)
class Span:
    """A link target and where it sits in the text.

    Attributes
    ----------
    line : int
        The one-based line number.
    start : int
        Offset of the target within its line.
    end : int
        Offset just past the target.
    target : str
        The target exactly as written, fragment included.
    reference : bool
        Whether the target belongs to a reference definition.
    """

    line: int
    start: int
    end: int
    target: str
    reference: bool = False


@dc.dataclass(frozen=True, slots=True)
class Change:
    """One rewritten link.

    Attributes
    ----------
    line : int
        The one-based line number.
    old : str
        The target before.
    new : str
        The target after.
    """

    line: int
    old: str
    new: str


def link_spans(text: str) -> list[Span]:
    """Locate every rewritable link target outside code.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[Span]
        Inline links and reference definitions, never those in fences or code
        spans, in document order.
    """
    spans: list[Span] = []
    for number, line in mm.unfenced_lines(text):
        definition = mm.REFERENCE_DEFINITION.match(line)
        if definition:
            spans.append(
                Span(number, *definition.span(1), definition[1], reference=True)
            )
        code = [found.span() for found in mm.CODE_SPAN.finditer(line)]
        spans.extend(
            Span(number, *found.span(1), found[1])
            for found in mm.INLINE_LINK.finditer(line)
            if not any(a <= found.start(1) < b for a, b in code)
        )
    return spans


def is_local(path: str) -> bool:
    """Say whether a link path names a file relative to the linking document.

    Parameters
    ----------
    path : str
        The link without its fragment.

    Returns
    -------
    bool
        ``False`` for an empty path (same-file fragment), a URL scheme and an
        absolute path.
    """
    return bool(path) and not path.startswith("/") and not SCHEME.match(path)


def resolve(source: PurePosixPath, path: str) -> Resolution:
    """Resolve a link path from a document without touching the disk.

    Parameters
    ----------
    source : pathlib.PurePosixPath
        The linking document's path from the repository root.
    path : str
        The link path, percent-encoding included, without its fragment.

    Returns
    -------
    tuple[int, tuple[str, ...]]
        Levels climbed above the root, then the remaining components.
    """
    return mm.lexical_target(source, urlparse.unquote(path))


def _relative(base: tuple[str, ...], target: Resolution) -> str:
    """Write the path from a directory to a resolved target.

    Parameters
    ----------
    base : tuple[str, ...]
        The linking document's directory, as components below the root.
    target : tuple[int, tuple[str, ...]]
        The resolved target.

    Returns
    -------
    str
        A relative path without a trailing slash; ``"."`` for the directory.
    """
    escapes, parts = target
    if escapes:
        return "/".join([".."] * (len(base) + escapes) + list(parts))
    common = 0
    for here, there in zip(base, parts, strict=False):
        if here != there:
            break
        common += 1
    return "/".join([".."] * (len(base) - common) + list(parts[common:])) or "."


def mapped(source: PurePosixPath, path: str, moves: Moves) -> Resolution:
    """Find where a link resolved before the move, after the move.

    Parameters
    ----------
    source : pathlib.PurePosixPath
        The linking document's old path.
    path : str
        The link path as written.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    tuple[int, tuple[str, ...]]
        The old resolution with a moved file replaced by its new location.
    """
    escapes, parts = resolve(source, path)
    if escapes == 0 and parts:
        parts = moves.get(PurePosixPath(*parts), PurePosixPath(*parts)).parts
    return escapes, tuple(parts)


def rewrite_link(link: str, source: PurePosixPath, moves: Moves) -> str:
    """Rewrite one link so that it still reaches its target after the moves.

    Parameters
    ----------
    link : str
        The target as written, ``path#fragment``.
    source : pathlib.PurePosixPath
        The linking document's old path.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path, for every moved file.

    Returns
    -------
    str
        ``link`` itself when it still holds from the document's new location,
        otherwise the relative path from there plus the original fragment.
    """
    path, hash_mark, fragment = link.partition("#")
    if not is_local(path):
        return link
    want = mapped(source, path, moves)
    here = moves.get(source, source)
    if resolve(here, path) == want:
        return link
    new = _relative(here.parent.parts, want)
    if path.endswith("/") and not new.endswith("/"):
        new += "/"
    if path != urlparse.unquote(path):
        new = urlparse.quote(new, safe="/")
    return f"{new}{hash_mark}{fragment}"


def rewrite_text(
    text: str, source: PurePosixPath, moves: Moves
) -> tuple[str, list[Change]]:
    """Rewrite every link of one document.

    Parameters
    ----------
    text : str
        The document's Markdown source.
    source : pathlib.PurePosixPath
        The document's old path.
    moves : Mapping[pathlib.PurePosixPath, pathlib.PurePosixPath]
        Old path to new path.

    Returns
    -------
    tuple[str, list[Change]]
        The new source, and one change per link that was rewritten.
    """
    lines = text.splitlines(keepends=True)
    changes: list[Change] = []
    for span in reversed(link_spans(text)):
        new = rewrite_link(span.target, source, moves)
        if new != span.target:
            line = lines[span.line - 1]
            lines[span.line - 1] = line[: span.start] + new + line[span.end :]
            changes.append(Change(span.line, span.target, new))
    return "".join(lines), sorted(changes, key=lambda change: change.line)
