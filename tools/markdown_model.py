"""A small Markdown model shared by the link checker and the audit tool.

It knows only what the repository's tools need: which lines lie outside code
fences, which headings those lines hold, what anchor each heading earns, which
explicit ``<a id>`` anchors exist, and which link targets the prose names.

The heading rule is the one used by the gap-analysis renderer's
``section_inventory``: lowercase, drop every character other than word
characters, hyphens and spaces, then replace spaces with hyphens. Headings
inside code fences are ignored. A test pins this module against the 543
anchors recorded in audit revision 89.
"""

import dataclasses as dc
import re
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import PurePath

FENCE = re.compile(r"^\s*(`{3,}|~{3,})")
HEADING = re.compile(r"^(#{1,6}) (.+)$")
CODE_SPAN = re.compile(r"(`+)[^`]*?\1")
INLINE_LINK = re.compile(r"""\]\(\s*<?([^)\s>]+)>?(?:\s+(?:"[^"]*"|'[^']*'))?\s*\)""")
REFERENCE_DEFINITION = re.compile(r"^ {0,3}\[(?!\^)[^\]]+\]:\s+<?([^\s>]+)>?")
EXPLICIT_ANCHOR = re.compile(r"""<a\s+[^>]*?\b(?:id|name)\s*=\s*["']([^"']+)["']""")


class Section(typ.TypedDict):
    """One heading and the lines it governs, as recorded in ``sections.json``."""

    heading: str
    level: int
    line_start: int
    line_end: int
    anchor: str


@dc.dataclass(frozen=True, slots=True)
class Link:
    """A link target found in prose.

    Attributes
    ----------
    target : str
        The destination exactly as written, fragment included.
    line : int
        The one-based line number on which the link appears.
    """

    target: str
    line: int


def slug(title: str) -> str:
    """Return the anchor that a heading title earns.

    Parameters
    ----------
    title : str
        The heading text without its ``#`` markers.

    Returns
    -------
    str
        The lowercased title without punctuation, spaces replaced by hyphens.
    """
    return re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-")


def unfenced_lines(text: str) -> cabc.Iterator[tuple[int, str]]:
    """Yield each line that lies outside a fenced code block.

    A fence opens at a line of three or more backticks or tildes and closes at
    the next fence line that uses the same character, as the renderer does.

    Parameters
    ----------
    text : str
        The Markdown source.

    Yields
    ------
    tuple[int, str]
        The one-based line number and the line.
    """
    fence: str | None = None
    for number, line in enumerate(text.splitlines(), 1):
        marker = FENCE.match(line)
        if marker:
            token = marker[1][0]
            fence = None if fence == token else token
        elif fence is None:
            yield number, line


def section_inventory(text: str) -> list[Section]:
    """List every heading of ``text`` with its line range and anchor.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[Section]
        One entry per heading, in order. A section ends on the line before the
        next heading, or on the last line of the text.
    """
    sections: list[Section] = []
    total = len(text.splitlines())
    for number, line in unfenced_lines(text):
        heading = HEADING.match(line)
        if heading is None:
            continue
        if sections:
            sections[-1]["line_end"] = number - 1
        sections.append({
            "heading": heading[2],
            "level": len(heading[1]),
            "line_start": number,
            "line_end": total,
            "anchor": slug(heading[2]),
        })
    return sections


def extract_links(text: str) -> list[Link]:
    """Find the inline links and reference definitions outside code.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[Link]
        Each link target with its line number. Links inside fenced blocks and
        inline code spans are ignored.
    """
    links: list[Link] = []
    for number, line in unfenced_lines(text):
        definition = REFERENCE_DEFINITION.match(line)
        if definition:
            links.append(Link(definition[1], number))
        prose = CODE_SPAN.sub("", line)
        links.extend(Link(found[1], number) for found in INLINE_LINK.finditer(prose))
    return links


def explicit_anchors(text: str) -> set[str]:
    """Collect the ``<a id>`` and ``<a name>`` anchors outside code fences.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    set[str]
        The declared anchor names.
    """
    found: set[str] = set()
    for _, line in unfenced_lines(text):
        found.update(match[1] for match in EXPLICIT_ANCHOR.finditer(line))
    return found


def lexical_target(source: PurePath, path: str) -> tuple[int, tuple[str, ...]]:
    """Resolve ``path`` against ``source``'s directory without touching disk.

    Parameters
    ----------
    source : pathlib.PurePath
        The linking file, relative to the repository root.
    path : str
        The link path, without its fragment.

    Returns
    -------
    tuple[int, tuple[str, ...]]
        How many levels the path climbs above the root, and the remaining path
        components.
    """
    parts = list(source.parent.parts)
    escapes = 0
    for part in path.split("/"):
        if part in {"", "."}:
            continue
        if part != "..":
            parts.append(part)
        elif parts:
            parts.pop()
        else:
            escapes += 1
    return escapes, tuple(parts)
