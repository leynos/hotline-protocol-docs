"""Find the status claims of a block and compare them with the register.

The rule is finite by design. It recognises the phrasings listed in
:data:`PHRASES` (the survey of the documents found no others that bind a status
to a gap), and binds each phrase to the gap identifiers earlier in its clause.
"""

import dataclasses as dc
import re
import typing as typ

from evidence_cites import Finding, gap_ids

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    from evidence_blocks import Block

RULE = "status"
RESOLVED = "Resolved"
NOT_RESOLVED = "not-resolved"
BOUNDARY = re.compile(
    r"(?<=[.!?])\s|[;:]\s|\s[\N{EN DASH}\N{EM DASH}]\s"
    r"|,\s+(?:while|but|whereas|although)\s"
)
SENTENCE = re.compile(r"(?<=[.!?])\s+")
LEAVE = "leave GAP-N open"

# The verb group that precedes a status word.
_STAY = r"(?:remains?|stays?|(?:is|are)(?:\s+(?:still|now|currently))?|still)"
_RESOLVED_VERB = (
    r"(?:is|are|was|were|has\s+been|have\s+been)(?:\s+(?:now|already|marked))*"
)
# Phrase name -> (claim kind, pattern). A kind is ``not-resolved`` (the gap is
# not Resolved), a register status word, or ``Resolved``.
PHRASES: dict[str, tuple[str, str]] = {
    "remain/stay/is open": (NOT_RESOLVED, rf"\b{_STAY}\s+open\b"),
    "remain/stay/is unresolved": (NOT_RESOLVED, rf"\b{_STAY}\s+unresolved\b"),
    "not resolved/closed": (
        NOT_RESOLVED,
        rf"\b{_STAY}\s+not\s+(?:yet\s+)?(?:[Rr]esolved|closed)\b",
    ),
    LEAVE: (NOT_RESOLVED, r"\b(?:leaves?|left|keeps?)\s+GAP-\d{3}[/\d]*\s+open\b"),
    "remain/stay/is Investigating": (
        "Investigating",
        rf"\b{_STAY}\s+Investigating\b",
    ),
    "remain/stay/is Open": ("Open", rf"\b{_STAY}\s+Open\b"),
    "is/was resolved/closed": (
        RESOLVED,
        rf"\b{_RESOLVED_VERB}\s+(?:[Rr]esolved|closed)\b",
    ),
}
_COMPILED = {name: (kind, re.compile(p)) for name, (kind, p) in PHRASES.items()}


@dc.dataclass(frozen=True, slots=True)
class Candidate:
    """A contradiction that a note may still accept.

    Attributes
    ----------
    finding : Finding
        The finding to report if nothing accepts it.
    gap : str
        The gap whose status is contradicted.
    section_end : int
        The last line of the section that holds the sentence.
    """

    finding: Finding
    gap: str
    section_end: int


@dc.dataclass(frozen=True, slots=True)
class Claim:
    """One status phrase and the gaps it binds to.

    Attributes
    ----------
    offset : int
        Where the phrase starts in the block text.
    name : str
        The phrase's name in :data:`PHRASES`.
    kind : str
        What the phrase claims.
    gaps : tuple[str, ...]
        The gap identifiers earlier in its clause.
    """

    offset: int
    name: str
    kind: str
    gaps: tuple[str, ...]


def _clause_start(text: str, position: int) -> int:
    """Find where the clause that holds ``position`` begins.

    Parameters
    ----------
    text : str
        Visible block text.
    position : int
        An offset in ``text``.

    Returns
    -------
    int
        The offset just after the last clause boundary before ``position``.
    """
    start = 0
    for boundary in BOUNDARY.finditer(text, 0, position):
        start = boundary.end()
    return start


def _contradicts(kind: str, actual: str) -> bool:
    """Say whether a claim of ``kind`` contradicts a register status.

    Parameters
    ----------
    kind : str
        ``not-resolved``, ``Resolved``, ``Open`` or ``Investigating``.
    actual : str
        The register's status for the gap.

    Returns
    -------
    bool
        ``True`` when the claim cannot hold.
    """
    if kind == NOT_RESOLVED:
        return actual == RESOLVED
    return actual != kind


def claims(text: str) -> list[Claim]:
    """Find the status claims of a block.

    A phrase binds to the gap identifiers that stand before it in its clause.
    A clause starts at a boundary (a sentence end, a semicolon, a colon, a dash
    or a contrastive conjunction) or just after the previous phrase, so that
    ``GAP-001 is Resolved and GAP-002 remains open`` is two claims.

    Parameters
    ----------
    text : str
        Visible block text.

    Returns
    -------
    list[Claim]
        The claims that bind at least one gap, in order of appearance.
    """
    matches = sorted(
        (m.start(), m.end(), name)
        for name, (_, pattern) in _COMPILED.items()
        for m in pattern.finditer(text)
    )
    found: list[Claim] = []
    previous_end = 0
    for start, end, name in matches:
        begin = max(_clause_start(text, start), previous_end)
        clause = text[start:end] if name == LEAVE else text[begin:start]
        previous_end = max(previous_end, end)
        bound = tuple(dict.fromkeys(gap_ids(clause)))
        if bound:
            found.append(Claim(start, name, _COMPILED[name][0], bound))
    return found


def sentence_at(text: str, offset: int) -> str:
    """Return the sentence of ``text`` that holds ``offset``.

    Parameters
    ----------
    text : str
        Visible block text.
    offset : int
        A character offset.

    Returns
    -------
    str
        The sentence.
    """
    start = 0
    for part in SENTENCE.split(text):
        end = text.find(part, start) + len(part)
        if offset < end:
            return part
        start = end
    return text


def block_candidates(
    path: str, block: Block, register: cabc.Mapping[str, str]
) -> tuple[list[Candidate], dict[str, int]]:
    """Find the contradictions of one block.

    Parameters
    ----------
    path : str
        The document's path.
    block : Block
        The block to read.
    register : collections.abc.Mapping[str, str]
        The register's status for each gap.

    Returns
    -------
    tuple[list[Candidate], dict[str, int]]
        The contradictions, and the number of matches of each phrase.
    """
    found: list[Candidate] = []
    counts: dict[str, int] = {}
    for claim in claims(block.text):
        counts[claim.name] = counts.get(claim.name, 0) + 1
        line = block.lines[min(claim.offset, len(block.lines) - 1)]
        sentence = sentence_at(block.text, claim.offset)
        for gap in claim.gaps:
            actual = register.get(gap)
            if actual is not None and _contradicts(claim.kind, actual):
                message = f"{gap} is {actual} in the register: {sentence}"
                key = f"{gap}: {claim.name}"
                finding = Finding(path, line, RULE, message, key)
                found.append(Candidate(finding, gap, block.section_end))
    return found, counts
