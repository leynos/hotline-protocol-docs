"""Find the headings of Markdown documents and check their local links.

The gap analysis report and its checks use these functions. They are
re-exported by ``render-protocol-gap-analysis.py``.
"""

import os
import re
import typing as typ
from pathlib import Path

MOTHRA_PREFIX = "../mothra/"


class Section(typ.TypedDict):
    """One Markdown heading and the snapshot lines it governs."""

    heading: str
    level: int
    line_start: int
    line_end: int
    anchor: str


def section_inventory(text: str) -> list[Section]:
    """List the headings outside fenced code blocks with their line spans.

    Parameters
    ----------
    text : str
        The Markdown document.

    Returns
    -------
    list[Section]
        One entry per heading, in document order.
    """
    sections: list[Section] = []
    fence = None
    lines = text.splitlines()
    for number, line in enumerate(lines, 1):
        marker = re.match(r"^\s*(`{3,}|~{3,})", line)
        if marker:
            token = marker[1][0]
            fence = None if fence == token else token
            continue
        if fence:
            continue
        heading = re.match(r"^(#{1,6}) (.+)$", line)
        if heading:
            title = heading[2]
            if sections:
                sections[-1]["line_end"] = number - 1
            sections.append({
                "heading": title,
                "level": len(heading[1]),
                "line_start": number,
                "line_end": len(lines),
                "anchor": re.sub(r"[^\w\- ]", "", title.lower()).replace(" ", "-"),
            })
    return sections


def mothra_checkout() -> Path:
    """Locate the general toolset checkout that a few links still point at.

    Returns
    -------
    Path
        ``MOTHRA_ROOT`` when it is set, otherwise the first sibling
        ``mothra`` directory found, otherwise the default sibling path.
    """
    if "MOTHRA_ROOT" in os.environ:
        return Path(os.environ["MOTHRA_ROOT"])
    root = Path(__file__).resolve().parent.parent
    for candidate in (root.parent / "mothra", root.parent.parent / "mothra"):
        if candidate.is_dir():
            return candidate
    return root.parent / "mothra"


def check_links(path: Path, text: str) -> int:
    """Check the local links and anchors of a document and count them.

    Parameters
    ----------
    path : Path
        The file that ``text`` came from; relative links resolve from it.
    text : str
        The Markdown text to check.

    Returns
    -------
    int
        The number of links examined.

    Raises
    ------
    ValueError
        If a link target or a fragment anchor does not exist.
    """
    links = re.findall(r"\]\(([^)\s]+)\)", text)
    links += re.findall(r"^\[[^\]]+\]: (\S+)", text, re.MULTILINE)
    for link in links:
        if "://" in link:
            continue
        relative, _, fragment = link.partition("#")
        target = (path.parent / relative).resolve() if relative else path.resolve()
        if relative.startswith(MOTHRA_PREFIX):
            # Guides that remain in the general toolset; see mothra_checkout().
            target = mothra_checkout() / relative.removeprefix(MOTHRA_PREFIX)
        if not target.exists() and target != path.resolve():
            message = f"Broken link in {path.name}: {link}"
            raise ValueError(message)
        if fragment and target.suffix == ".md":
            content = text if target == path.resolve() else target.read_text()
            anchors = {section["anchor"] for section in section_inventory(content)}
            if fragment not in anchors:
                message = f"Broken anchor in {path.name}: {link}"
                raise ValueError(message)
    return len(links)
