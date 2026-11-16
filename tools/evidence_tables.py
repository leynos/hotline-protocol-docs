"""Compare the ``Status`` column of each table with the register."""

import typing as typ

import markdown_model as mm
from evidence_cites import Finding, gap_ids
from evidence_claims import RULE, Candidate

if typ.TYPE_CHECKING:
    import collections.abc as cabc

STATUS_WORDS = ("Open", "Investigating", "Resolved")
STATUS_CELL = "status cell"


def _cells(line: str) -> list[str]:
    """Split a table row into stripped cells.

    Parameters
    ----------
    line : str
        A row.

    Returns
    -------
    list[str]
        The cells.
    """
    return [cell.strip() for cell in line.strip().strip("|").split("|")]


def _status_column(cells: list[str]) -> int:
    """Find the ``Status`` column of a table header.

    Parameters
    ----------
    cells : list[str]
        The header's cells.

    Returns
    -------
    int
        The column index, or ``-1`` when there is none.
    """
    names = [cell.lower() for cell in cells]
    return next((i for i, name in enumerate(names) if name.startswith("status")), -1)


def _cell_candidates(
    path: str,
    row: tuple[int, int, list[str]],
    status: tuple[int, cabc.Mapping[str, str]],
) -> list[Candidate]:
    """Compare one table row's status cell with the register.

    Parameters
    ----------
    path : str
        The document's path.
    row : tuple[int, int, list[str]]
        The row's line, the last line of its section and its cells.
    status : tuple[int, collections.abc.Mapping[str, str]]
        The status column and the register.

    Returns
    -------
    list[Candidate]
        One contradiction per gap in the first cell whose status differs.
    """
    (number, end, cells), (column, register) = row, status
    found: list[Candidate] = []
    for gap in gap_ids(cells[0]):
        actual = register.get(gap)
        if actual is not None and actual != cells[column]:
            message = f"{gap} is {cells[column]} here but {actual} in the register"
            key = f"{gap}: {STATUS_CELL} {cells[column]}"
            finding = Finding(path, number, RULE, message, key)
            found.append(Candidate(finding, gap, end))
    return found


def table_candidates(
    path: str, text: str, register: cabc.Mapping[str, str]
) -> tuple[list[Candidate], int]:
    """Compare the ``Status`` column of each table with the register.

    Parameters
    ----------
    path : str
        The document's path.
    text : str
        Its Markdown source.
    register : collections.abc.Mapping[str, str]
        The register's status for each gap.

    Returns
    -------
    tuple[list[Candidate], int]
        The contradictions, and how many status cells were compared.
    """
    sections = mm.section_inventory(text)
    found: list[Candidate] = []
    compared = 0
    column = -1
    header = True
    for number, line in mm.unfenced_lines(text):
        if not line.lstrip().startswith("|"):
            header = True
            continue
        cells = _cells(line)
        if header:
            column, header = _status_column(cells), False
        elif 0 <= column < len(cells) and cells[column] in STATUS_WORDS:
            compared += 1
            enclosing = [s["line_end"] for s in sections if s["line_start"] <= number]
            end = enclosing[-1] if enclosing else number
            found.extend(
                _cell_candidates(path, (number, end, cells), (column, register))
            )
    return found, compared
