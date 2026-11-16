"""Cut a Markdown document into the blocks that the status rule reads.

A block is a paragraph, a list item, a heading or one cell of a table row, with
the source line of every character kept so that a finding can name its line.
A blockquote paragraph that begins ``Status note`` is a note, not a block.
"""

import bisect
import dataclasses as dc
import re

import markdown_model as mm

LIST_START = re.compile(r"^\s*(?:[-*+]|\d+\.)\s")
NOTE_START = re.compile(r"^Status note\b")
QUOTE_PREFIX = re.compile(r"^\s*>\s?")
MARKUP = re.compile(
    r"\[(?P<link>[^\]]*)\]\([^)]*\)|\[(?P<ref>[^\]]*)\]\[[^\]]*\]|\*\*|\*|`|<br>"
)
UNRECONCILED = "Unreconciled:"


@dc.dataclass(frozen=True, slots=True)
class Block:
    """A run of prose that is read as one unit.

    Attributes
    ----------
    text : str
        The visible text, with link and emphasis syntax removed.
    lines : tuple[int, ...]
        The source line of each character of ``text``.
    section_end : int
        The last line of the section that holds the block.
    unreconciled : bool
        Whether the paragraph begins ``Unreconciled:``.
    """

    text: str
    lines: tuple[int, ...]
    section_end: int
    unreconciled: bool = False


@dc.dataclass(frozen=True, slots=True)
class Note:
    """A blockquote paragraph that begins ``Status note``.

    Attributes
    ----------
    line : int
        The line on which it starts.
    section_end : int
        The last line of the section that holds it.
    text : str
        The paragraph without quote markers.
    """

    line: int
    section_end: int
    text: str


class _Layout:
    """Find the end of the section that holds a line."""

    def __init__(self, text: str) -> None:
        """Index the headings of ``text``.

        Parameters
        ----------
        text : str
            The Markdown source.
        """
        self._sections = mm.section_inventory(text)
        self._starts = [section["line_start"] for section in self._sections]
        self._total = len(text.splitlines())

    def end_of(self, line: int) -> int:
        """Return the last line of the section that holds ``line``.

        Parameters
        ----------
        line : int
            A one-based line number.

        Returns
        -------
        int
            The section's last line; for lines before the first heading, the
            line before that heading.
        """
        index = bisect.bisect_right(self._starts, line) - 1
        if index >= 0:
            return self._sections[index]["line_end"]
        return self._starts[0] - 1 if self._starts else self._total


def _kind(line: str) -> str:
    """Classify a line by how it may continue.

    Parameters
    ----------
    line : str
        A non-blank line.

    Returns
    -------
    str
        ``table``, ``heading``, ``quote`` or ``text``.
    """
    stripped = line.lstrip()
    for marker, kind in (("|", "table"), ("#", "heading"), (">", "quote")):
        if stripped.startswith(marker):
            return kind
    return "text"


def _breaks(number: int, line: str, last: tuple[int, str]) -> bool:
    """Say whether ``line`` cannot continue the run that ends at ``last``.

    Parameters
    ----------
    number : int
        The line's number.
    line : str
        The line.
    last : tuple[int, str]
        The number and text of the run's last line.

    Returns
    -------
    bool
        ``True`` for a blank line, a gap in the numbering (a fence), a list
        item, a table row or heading, and a change of kind.
    """
    if not line.strip() or number != last[0] + 1:
        return True
    kind = _kind(line)
    return (
        LIST_START.match(line) is not None
        or kind in {"table", "heading"}
        or (kind != _kind(last[1]))
    )


def _groups(text: str) -> list[list[tuple[int, str]]]:
    """Group the unfenced lines of a document into runs.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[list[tuple[int, str]]]
        Each run as ``(line number, line)`` pairs.
    """
    groups: list[list[tuple[int, str]]] = []
    current: list[tuple[int, str]] = []
    for number, line in mm.unfenced_lines(text):
        if current and _breaks(number, line, current[-1]):
            groups.append(current)
            current = []
        if line.strip():
            current.append((number, line))
    return [group for group in [*groups, current] if group]


def strip_markup(text: str, lines: list[int]) -> tuple[str, tuple[int, ...]]:
    """Remove link and emphasis syntax, keeping a line number per character.

    Parameters
    ----------
    text : str
        Block text.
    lines : list[int]
        The source line of each character of ``text``.

    Returns
    -------
    tuple[str, tuple[int, ...]]
        The visible text and the line of each of its characters.
    """
    pieces: list[str] = []
    numbers: list[int] = []
    cursor = 0
    for match in MARKUP.finditer(text):
        keep = match["link"] if match["link"] is not None else match["ref"]
        pieces.append(text[cursor : match.start()])
        numbers.extend(lines[cursor : match.start()])
        if keep is not None:
            start = match.start() + 1
            pieces.append(keep)
            numbers.extend(lines[start : start + len(keep)])
        cursor = match.end()
    pieces.append(text[cursor:])
    numbers.extend(lines[cursor:])
    return "".join(pieces), tuple(numbers)


def _cell_blocks(number: int, line: str, end: int) -> list[Block]:
    """Make one block of each cell of a table row.

    Parameters
    ----------
    number : int
        The row's line number.
    line : str
        The row.
    end : int
        The last line of the section that holds the row.

    Returns
    -------
    list[Block]
        One block per non-empty cell.
    """
    cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
    return [
        Block(*strip_markup(cell, [number] * len(cell)), end) for cell in cells if cell
    ]


def _paragraph_block(group: list[tuple[int, str]], end: int) -> Block:
    """Make one block of a paragraph or list item.

    Parameters
    ----------
    group : list[tuple[int, str]]
        The lines of the run.
    end : int
        The last line of the section that holds it.

    Returns
    -------
    Block
        The block, with its visible text.
    """
    pieces = [QUOTE_PREFIX.sub("", line).strip() for _, line in group]
    raw = " ".join(pieces)
    chars = [
        number
        for (number, _), piece in zip(group, pieces, strict=True)
        for _ in range(len(piece) + 1)
    ]
    text, lines = strip_markup(raw, chars[: len(raw)])
    return Block(text, lines, end, raw.startswith(UNRECONCILED))


def read_blocks(text: str) -> tuple[list[Block], list[Note]]:
    """Cut the unfenced lines of a document into blocks and find its notes.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    tuple[list[Block], list[Note]]
        The blocks to read, and the status notes.
    """
    layout = _Layout(text)
    blocks: list[Block] = []
    notes: list[Note] = []
    for group in _groups(text):
        number, first = group[0]
        end = layout.end_of(number)
        raw = " ".join(QUOTE_PREFIX.sub("", line).strip() for _, line in group)
        if first.lstrip().startswith(">") and NOTE_START.match(raw):
            notes.append(Note(number, end, raw))
        elif first.lstrip().startswith("|"):
            blocks.extend(_cell_blocks(number, first, end))
        else:
            blocks.append(_paragraph_block(group, end))
    return blocks, notes
