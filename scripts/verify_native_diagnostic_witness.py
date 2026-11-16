"""Count the native transfer rows of a 303 reply and judge the count.

The verifiers in ``verify_native_diagnostic_existing`` re-export
:func:`section_witness`, and ``verify_native_pm_readback`` imports it from there.
"""

import re

from native_diagnostic_existing_cases import NAME

HEADINGS = (
    b"-------- File Downloads ---------",
    b"------- Folder Downloads --------",
    b"--------- File Uploads ----------",
    b"-------- Folder Uploads ---------",
    b"------- Waiting Downloads -------",
)
ACTIVE_SECTION = 0  # index in HEADINGS of the active downloads section
WAITING_SECTION = 4  # index in HEADINGS of the last section, the waiting downloads
UNRELATED_SECTIONS = (1, 2, 3)  # transfer sections that must read only "None."
ACTIVE_ROW = rb" +[0-9]{1,3}% +\S.*"  # a percentage and a transfer detail
WAITING_ROW = rb" +\(File\)"  # the file marker of a waiting row


def _heading_marker(heading: bytes) -> bytes:
    """Return a heading as it appears in the text, between two blank lines.

    Parameters
    ----------
    heading : bytes
        One entry of ``HEADINGS``.

    Returns
    -------
    bytes
        The heading framed by carriage returns.
    """
    return b"\r\r" + heading + b"\r\r"


def _split_sections(
    text: bytes,
) -> tuple[str | None, dict[int, list[bytes]], dict[int, bool]]:
    """Split ``text`` at its headings, stopping at the first missing section.

    Parameters
    ----------
    text : bytes
        The field 101 text of a 303 reply.

    Returns
    -------
    tuple[str | None, dict[int, list[bytes]], dict[int, bool]]
        The reason the split failed, or ``None``; the rows of each section reached;
        and whether each section reached ends with a carriage return.
    """
    sections: dict[int, list[bytes]] = {}
    terminated: dict[int, bool] = {}
    rest = text
    for index, heading in enumerate(HEADINGS):
        marker = _heading_marker(heading)
        if marker not in rest:
            return f"Missing complete section {index}", sections, terminated
        _, _, rest = rest.partition(marker)
        if index + 1 < len(HEADINGS):
            next_marker = _heading_marker(HEADINGS[index + 1])
            if next_marker not in rest:
                return f"Section {index} has no terminator", sections, terminated
            body, _, rest = rest.partition(next_marker)
            # Keep the next heading for the following iteration.
            rest = next_marker + rest
        else:
            body = rest
        terminated[index] = body.endswith(b"\r")
        sections[index] = body.rstrip(b"\r").split(b"\r")
    return None, sections, terminated


def _row_matches(index: int, line: bytes) -> bool:
    """Return whether ``line`` is a complete row of the section at ``index``.

    Parameters
    ----------
    index : int
        The index in ``HEADINGS`` of the section that holds the row.
    line : bytes
        One row of the section.

    Returns
    -------
    bool
        Whether the row is the fixture name followed by the section's row detail.
    """
    suffix = ACTIVE_ROW if index == ACTIVE_SECTION else WAITING_ROW
    return re.fullmatch(re.escape(NAME) + suffix, line) is not None


def _rows_complete(index: int, lines: list[bytes], terminated: dict[int, bool]) -> bool:
    """Return whether the rows of one section are all complete rows.

    Parameters
    ----------
    index : int
        The index in ``HEADINGS`` of the section.
    lines : list[bytes]
        The rows of the section.
    terminated : dict[int, bool]
        Whether the section ends with a carriage return; the waiting section must.

    Returns
    -------
    bool
        Whether the section is closed and every row matches.
    """
    closed = index < WAITING_SECTION or terminated[index]
    return closed and all(_row_matches(index, line) for line in lines)


def _count_rows(
    sections: dict[int, list[bytes]], terminated: dict[int, bool]
) -> tuple[dict[str, int], str | None]:
    """Count the rows of the active and waiting sections.

    Parameters
    ----------
    sections : dict[int, list[bytes]]
        The rows of each section.
    terminated : dict[int, bool]
        Whether each section ends with a carriage return.

    Returns
    -------
    tuple[dict[str, int], str | None]
        The count of each section counted so far, and the label of the first section
        whose rows are incomplete or foreign, or ``None`` when both are complete.
    """
    counts: dict[str, int] = {}
    for index, label in ((ACTIVE_SECTION, "active"), (WAITING_SECTION, "waiting")):
        lines = sections[index]
        if lines == [b"None."]:
            counts[label] = 0
        elif _rows_complete(index, lines, terminated):
            counts[label] = len(lines)
        else:
            return counts, label
    return counts, None


def section_witness(text: bytes, active: int, waiting: int) -> dict:
    """Count complete native rows; never equate an incomplete section with proof.

    Parameters
    ----------
    text : bytes
        The field 101 text of a 303 reply.
    active : int
        The number of active rows that the planned density point predicts.
    waiting : int
        The number of waiting rows that the planned density point predicts.

    Returns
    -------
    dict
        The witness, with its ``status`` of ``"complete"`` or ``"incomplete"``, the
        expected and observed counts, and the ``reason`` when it is not complete.
    """
    result = {
        "expected_active": active,
        "expected_waiting": waiting,
        "field101_bytes": len(text),
        "status": "incomplete",
    }
    reason, sections, terminated = _split_sections(text)
    if reason is not None:
        return {**result, "reason": reason}
    if any(sections[index] != [b"None."] for index in UNRELATED_SECTIONS):
        return {**result, "reason": "Unrelated transfer section is nonempty"}
    counts, failed = _count_rows(sections, terminated)
    if failed is not None:
        return {
            **result,
            "reason": f"Incomplete or foreign {failed} row",
            "observed_counts": counts,
        }
    result["observed_counts"] = counts
    if counts == {"active": active, "waiting": waiting}:
        result["status"] = "complete"
    else:
        result["reason"] = "Row counts differ from the planned density point"
    return result
