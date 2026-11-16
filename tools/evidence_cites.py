"""Find what a document cites: evidence corpora, ledger and gap identifiers, scripts.

Citations are read from the whole text of a document, fenced blocks included,
because a recorded command or JSON object cites as surely as prose does. Each
citation carries the line it stands on and the heading of the section that
holds it, so that an index can link to the section.
"""

import bisect
import dataclasses as dc
import re
from pathlib import PurePath, PurePosixPath

import markdown_model as mm
from evidence_corpus import corpus_of
from evidence_files import cited_paths

LEDGER_ID = re.compile(r"(?<![\w-])[VM]\d{3}(?![\w-])")
GAP_ID = re.compile(r"GAP-(\d{3})((?:/\d{3})*)")
SCRIPT = re.compile(r"(?<![\w./-])(?:\.\./)*(scripts/[\w./-]*\w)(?![\w*<>{}$\[])")
EXTERNAL = ("mailto:", "http://", "https://")


@dc.dataclass(frozen=True, slots=True, order=True)
class Finding:
    """One thing that a check found wrong.

    Attributes
    ----------
    rule : str
        The rule that found it, for example ``gap-id`` or ``status``.
    path : str
        The repository-relative file.
    line : int
        The one-based line.
    message : str
        What is wrong.
    key : str
        A stable identity inside the file and rule, matched by ``--known``.
    """

    path: str
    line: int
    rule: str
    message: str
    key: str

    def render(self) -> str:
        """Render the finding as ``file:line: rule: message``.

        Returns
        -------
        str
            The report line.
        """
        return f"{self.path}:{self.line}: {self.rule}: {self.message}"


@dc.dataclass(frozen=True, slots=True, order=True)
class Occurrence:
    """One citation at a place in a document.

    Attributes
    ----------
    value : str
        The identifier, corpus path or script path.
    line : int
        The one-based line of the citation.
    heading : str
        The text of the nearest heading above it, or empty before the first.
    anchor : str
        That heading's anchor, or empty.
    """

    value: str
    line: int
    heading: str = ""
    anchor: str = ""


@dc.dataclass(slots=True)
class DocCites:
    """Everything one document cites.

    Attributes
    ----------
    path : str
        The repository-relative path of the document.
    ledger : list[Occurrence]
        Ledger identifiers such as ``V001`` and ``M001``.
    gaps : list[Occurrence]
        Gap identifiers such as ``GAP-044``.
    corpora : list[Occurrence]
        Corpus paths named by evidence citations.
    scripts : list[Occurrence]
        Script paths cited in a code span, a link target or a fenced block.
    evidence_links : int
        How many links point into ``evidence/``.
    """

    path: str
    ledger: list[Occurrence] = dc.field(default_factory=list)
    gaps: list[Occurrence] = dc.field(default_factory=list)
    corpora: list[Occurrence] = dc.field(default_factory=list)
    scripts: list[Occurrence] = dc.field(default_factory=list)
    evidence_links: int = 0


def gap_ids(text: str) -> list[str]:
    """List the gap identifiers in ``text``, expanding ``GAP-015/016``.

    Parameters
    ----------
    text : str
        Any text.

    Returns
    -------
    list[str]
        Identifiers such as ``GAP-015``, in order of appearance.
    """
    found: list[str] = []
    for match in GAP_ID.finditer(text):
        found.append(f"GAP-{match[1]}")
        found.extend(f"GAP-{tail}" for tail in match[2].split("/") if tail)
    return found


class _Sections:
    """Look up the heading that governs a line."""

    def __init__(self, text: str) -> None:
        """Index the headings of ``text``.

        Parameters
        ----------
        text : str
            The Markdown source.
        """
        self._sections = mm.section_inventory(text)
        self._starts = [section["line_start"] for section in self._sections]

    def locate(self, value: str, line: int) -> Occurrence:
        """Build the occurrence of ``value`` at ``line``.

        Parameters
        ----------
        value : str
            The cited value.
        line : int
            Its one-based line.

        Returns
        -------
        Occurrence
            The value with its heading and anchor.
        """
        index = bisect.bisect_right(self._starts, line) - 1
        if index < 0:
            return Occurrence(value, line)
        section = self._sections[index]
        return Occurrence(value, line, section["heading"], section["anchor"])


def _script_candidates(text: str) -> list[tuple[int, str]]:
    """Find script paths in code spans, link targets and fenced blocks.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    list[tuple[int, str]]
        The line and the repository-relative script path of each citation.
    """
    unfenced = dict(mm.unfenced_lines(text))
    found: list[tuple[int, str]] = []
    for number, line in enumerate(text.splitlines(), 1):
        if number in unfenced:
            spans = [m[0].strip("`") for m in mm.CODE_SPAN.finditer(line)]
            spans += [m[1] for m in mm.INLINE_LINK.finditer(line)]
            scanned = " ".join(spans)
        else:
            scanned = line
        found.extend((number, m[1]) for m in SCRIPT.finditer(scanned))
    return found


def _evidence_links(path: PurePath, text: str) -> int:
    """Count the links of a document that point into ``evidence/``.

    Parameters
    ----------
    path : pathlib.PurePath
        The document, relative to the root.
    text : str
        Its source.

    Returns
    -------
    int
        The number of links whose resolved target lies below ``evidence/``.
    """
    count = 0
    for link in mm.extract_links(text):
        target = link.target.partition("#")[0]
        if not target or target.startswith(EXTERNAL):
            continue
        escapes, parts = mm.lexical_target(path, target)
        if escapes == 0 and parts[:1] == ("evidence",):
            count += 1
    return count


def scan_document(path: str, text: str) -> DocCites:
    """Collect the citations of one document.

    Parameters
    ----------
    path : str
        The document's repository-relative POSIX path.
    text : str
        Its Markdown source.

    Returns
    -------
    DocCites
        Ledger identifiers, gap identifiers, corpora, scripts and the count of
        evidence links.
    """
    sections = _Sections(text)
    cites = DocCites(path, evidence_links=_evidence_links(PurePosixPath(path), text))
    for number, line in enumerate(text.splitlines(), 1):
        cites.ledger.extend(
            sections.locate(m[0], number) for m in LEDGER_ID.finditer(line)
        )
        cites.gaps.extend(sections.locate(i, number) for i in gap_ids(line))
        corpora = {corpus_of(p) for p in cited_paths(line.encode("utf-8"))}
        cites.corpora.extend(
            sections.locate(c, number) for c in sorted(corpora) if c is not None
        )
    cites.scripts.extend(
        sections.locate(value, number) for number, value in _script_candidates(text)
    )
    return cites
