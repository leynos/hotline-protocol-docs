"""Find sentences that state a gap status the register contradicts (INV-STATUS).

Claims are read by :mod:`evidence_claims` and table cells by
:mod:`evidence_tables`; this module reads the notes that supersede a claim and
assembles the findings of one document.

A contradicting sentence is accepted when a dated supersession note for the
same gap follows within the same section. The note is a blockquote paragraph
that begins ``> Status note (YYYY-MM-DD):``, names the gap, and states the
register's current status word. Paragraphs that begin ``Unreconciled:`` set two
sides of a disagreement against each other and are not read by this rule.
"""

import dataclasses as dc
import datetime as dt
import re
import typing as typ

from evidence_blocks import Block, Note, read_blocks
from evidence_cites import Finding, gap_ids
from evidence_claims import RESOLVED, SENTENCE, Candidate, block_candidates
from evidence_tables import STATUS_CELL, table_candidates

if typ.TYPE_CHECKING:
    import collections.abc as cabc

NOTE_RULE = "status-note"
NOTE = re.compile(r"^Status note \((\d{4}-\d{2}-\d{2})\):")


@dc.dataclass(slots=True)
class StatusScan:
    """The outcome of reading one document for status claims.

    Attributes
    ----------
    findings : list[Finding]
        Contradictions not covered by a note, and malformed notes.
    accepted : int
        Contradictions that a valid note accepts.
    resolved_sentences : list[tuple[int, str]]
        Every sentence that names a Resolved gap, with its line, for review.
    phrases : dict[str, int]
        How many times each phrasing matched, and how many status cells were
        compared.
    """

    findings: list[Finding] = dc.field(default_factory=list)
    accepted: int = 0
    resolved_sentences: list[tuple[int, str]] = dc.field(default_factory=list)
    phrases: dict[str, int] = dc.field(default_factory=dict)


def parse_note(text: str) -> bool:
    """Say whether a note begins with a valid dated status-note marker.

    Parameters
    ----------
    text : str
        The note's text without quote markers.

    Returns
    -------
    bool
        ``True`` for ``Status note (YYYY-MM-DD):`` with a real date.
    """
    dated = NOTE.match(text)
    if dated is None:
        return False
    try:
        dt.date.fromisoformat(dated[1])
    except ValueError:
        return False
    return True


def _supersedes(note: Note, candidate: Candidate, actual: str) -> bool:
    """Say whether a note supersedes a contradicting sentence.

    Parameters
    ----------
    note : Note
        A status note.
    candidate : Candidate
        The contradiction.
    actual : str
        The register's status for the gap.

    Returns
    -------
    bool
        ``True`` when the note follows the sentence in the same section, is
        dated, names the gap and states the status.
    """
    follows = candidate.finding.line < note.line
    if not follows or note.section_end != candidate.section_end:
        return False
    names_gap = candidate.gap in gap_ids(note.text)
    return parse_note(note.text) and names_gap and actual in note.text


def _resolved_sentences(
    block: Block, register: cabc.Mapping[str, str]
) -> list[tuple[int, str]]:
    """List the sentences of a block that name a Resolved gap.

    Parameters
    ----------
    block : Block
        A block.
    register : collections.abc.Mapping[str, str]
        The register's status for each gap.

    Returns
    -------
    list[tuple[int, str]]
        The line and sentence, one entry per sentence.
    """
    found: list[tuple[int, str]] = []
    start = 0
    for part in SENTENCE.split(block.text):
        begin = block.text.find(part, start)
        start = begin + len(part)
        if any(register.get(gap) == RESOLVED for gap in gap_ids(part)):
            found.append((block.lines[min(begin, len(block.lines) - 1)], part))
    return found


def _bad_notes(path: str, notes: list[Note]) -> list[Finding]:
    """Report the notes that begin ``Status note`` but are not well formed.

    Parameters
    ----------
    path : str
        The document's path.
    notes : list[Note]
        The document's notes.

    Returns
    -------
    list[Finding]
        One finding per malformed note.
    """
    message = "a status note must begin `> Status note (YYYY-MM-DD):`"
    return [
        Finding(path, note.line, NOTE_RULE, message, note.text[:40])
        for note in notes
        if not parse_note(note.text)
    ]


def scan_status(path: str, text: str, register: cabc.Mapping[str, str]) -> StatusScan:
    """Read one document for status claims that contradict the register.

    Parameters
    ----------
    path : str
        The document's repository-relative path.
    text : str
        Its Markdown source.
    register : collections.abc.Mapping[str, str]
        The register's status for each gap identifier.

    Returns
    -------
    StatusScan
        The findings, the count of accepted contradictions, every sentence that
        names a Resolved gap, and the phrase counts.
    """
    blocks, notes = read_blocks(text)
    scan = StatusScan(findings=_bad_notes(path, notes))
    candidates, compared = table_candidates(path, text, register)
    if compared:
        scan.phrases[STATUS_CELL] = compared
    for block in blocks:
        scan.resolved_sentences.extend(_resolved_sentences(block, register))
        if block.unreconciled:
            continue
        found, counts = block_candidates(path, block, register)
        candidates.extend(found)
        for name, count in counts.items():
            scan.phrases[name] = scan.phrases.get(name, 0) + count
    for candidate in candidates:
        actual = register[candidate.gap]
        if any(_supersedes(note, candidate, actual) for note in notes):
            scan.accepted += 1
        else:
            scan.findings.append(candidate.finding)
    return scan
