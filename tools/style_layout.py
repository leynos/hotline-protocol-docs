"""Check the layout rules: table captions, figure paragraphs and fence labels.

Every table is followed, after one blank line, by a caption paragraph
``_Table N: ..._``. Every Mermaid block is preceded by a paragraph that begins
``For screen readers:`` and followed, after one blank line, by a caption
``_Figure N: ..._``. Both kinds of caption are numbered consecutively from 1
within the document, and every fenced block carries a language label.
"""

import dataclasses as dc
import re

import markdown_model as mm
from evidence_cites import Finding

TABLE_RULE = "table-caption"
FIGURE_RULE = "figure"
FENCE_RULE = "code-fence"
SCREEN_READERS = "For screen readers:"
CAPTION = re.compile(r"^_(Table|Figure) (\d+): .*_$", re.DOTALL)
MERMAID = "mermaid"
KEY_WIDTH = 60


@dc.dataclass(slots=True)
class Layout:
    """What the layout rules found in one document.

    Attributes
    ----------
    findings : list[Finding]
        The violations.
    tables : int
        How many tables the document holds.
    figures : int
        How many Mermaid blocks the document holds.
    """

    findings: list[Finding] = dc.field(default_factory=list)
    tables: int = 0
    figures: int = 0


def _paragraph(lines: list[str], first: int) -> str:
    """Join the paragraph that starts at an index.

    Parameters
    ----------
    lines : list[str]
        The document's lines.
    first : int
        The zero-based index of the paragraph's first line.

    Returns
    -------
    str
        The paragraph's lines, joined by spaces; empty past the end.
    """
    found: list[str] = []
    for line in lines[first:]:
        if not line.strip():
            break
        found.append(line.strip())
    return " ".join(found)


def _paragraph_before(lines: list[str], line: int) -> str:
    """Return the nearest paragraph that ends before a line.

    Parameters
    ----------
    lines : list[str]
        The document's lines.
    line : int
        The one-based line that the paragraph must precede.

    Returns
    -------
    str
        The paragraph, joined by spaces; empty when none precedes the line.
    """
    index = line - 2
    while index >= 0 and not lines[index].strip():
        index -= 1
    end = index
    while index >= 0 and lines[index].strip():
        index -= 1
    return " ".join(part.strip() for part in lines[index + 1 : end + 1])


def _caption(lines: list[str], last: int, kind: str, number: int) -> str | None:
    """Say what is wrong with the caption that follows a table or figure.

    Parameters
    ----------
    lines : list[str]
        The document's lines.
    last : int
        The one-based last line of the table or block.
    kind : str
        ``Table`` or ``Figure``.
    number : int
        The number that the caption must carry.

    Returns
    -------
    str | None
        The fault, or ``None`` when the caption conforms.
    """
    blank_ok = last < len(lines) and not lines[last].strip()
    found = CAPTION.match(_paragraph(lines, last + 1)) if blank_ok else None
    if found is None or found[1] != kind:
        return f"{kind.lower()} {number} has no caption `_{kind} {number}: ..._`"
    if int(found[2]) != number:
        return f"caption is numbered {found[2]}; it must be {kind} {number}"
    return None


def _header(lines: list[str], first: int) -> str:
    """Name a table by its header row, for a stable key.

    Parameters
    ----------
    lines : list[str]
        The document's lines.
    first : int
        The one-based first line of the table.

    Returns
    -------
    str
        The header row without spacing, cut to a fixed width.
    """
    return re.sub(r"\s+", " ", lines[first - 1]).strip()[:KEY_WIDTH]


def layout_findings(path: str, text: str, *, tables_only: bool = False) -> Layout:
    """Apply the layout rules to one document.

    Parameters
    ----------
    path : str
        The document's repository-relative path.
    text : str
        Its Markdown source.
    tables_only : bool
        Apply only the table rule, as for a generated index.

    Returns
    -------
    Layout
        The findings and the counts of tables and Mermaid blocks.
    """
    lines = text.splitlines()
    result = Layout()
    for number, (first, last) in enumerate(mm.table_spans(text), 1):
        result.tables += 1
        fault = _caption(lines, last, "Table", number)
        if fault:
            key = f"table: {_header(lines, first)}"
            result.findings.append(Finding(path, first, TABLE_RULE, fault, key))
    if tables_only:
        return result
    for fence in mm.fences(text):
        if not fence.info:
            body = lines[fence.start] if fence.start < len(lines) else ""
            key = f"unlabelled fence: {body.strip()[:KEY_WIDTH]}"
            message = "the fenced block has no language label"
            result.findings.append(Finding(path, fence.start, FENCE_RULE, message, key))
        elif fence.info.split()[0] == MERMAID:
            _figure(path, lines, fence, result)
    return result


def _figure(path: str, lines: list[str], fence: mm.Fence, result: Layout) -> None:
    """Apply the figure rule to one Mermaid block.

    Parameters
    ----------
    path : str
        The document's path.
    lines : list[str]
        The document's lines.
    fence : markdown_model.Fence
        The block.
    result : Layout
        The result to extend.
    """
    result.figures += 1
    number = result.figures
    key = f"mermaid block {number}"
    if not _paragraph_before(lines, fence.start).startswith(SCREEN_READERS):
        message = f"the diagram is not preceded by a `{SCREEN_READERS}` paragraph"
        result.findings.append(Finding(path, fence.start, FIGURE_RULE, message, key))
    fault = _caption(lines, fence.end, "Figure", number)
    if fault:
        result.findings.append(
            Finding(path, fence.start, FIGURE_RULE, fault, f"{key} caption")
        )
