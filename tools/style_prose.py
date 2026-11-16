"""Check the prose rules: heading case and the person of the text.

Sentence case cannot be decided mechanically. A heading word after the first is
reported only when it is capitalized, is not an acronym, an identifier or a
listed term, and the corpus also writes it in lower case. A capitalized word
that the corpus never writes in lower case is probably a proper noun, so it is
listed as undecided instead of reported, as is a word after a colon or inside
quotation marks.
"""

import dataclasses as dc
import re
import typing as typ

import markdown_model as mm
from evidence_cites import Finding

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CASE_RULE = "heading-case"
PERSON_RULE = "person"
KEY_WIDTH = 60
MIN_LETTERS = 2
PERSON = re.compile(
    r"(?<![\w/.-])(?:I|[Ww]e|[Oo]ur|[Oo]urs|[Oo]urselves|[Uu]s|[Yy]ou|[Yy]our"
    r"|[Yy]ours|[Yy]ourself|[Mm]y|[Mm]e)(?![\w/-])"
)
QUOTED = re.compile(r'"[^"]*"|“[^”]*”')
LINK_TARGET = re.compile(r"\]\([^)]*\)|<https?://[^>]*>")
HEADING_LINK = re.compile(r"\[([^\]]*)\]\([^)]*\)")
SECTION_NUMBER = re.compile(r"^\d+(?:\.\d+)*\.?$")
LOWER_WORD = re.compile(r"\b[a-z]{3,}\b")
EDGE = "()[]{}\"'\u201c\u201d\u2018\u2019,;.!?"


@dc.dataclass(frozen=True, slots=True)
class Undecided:
    """A heading word that the case rule cannot judge.

    Attributes
    ----------
    path : str
        The document.
    line : int
        The heading's line.
    word : str
        The word.
    reason : str
        Why the rule cannot decide.
    heading : str
        The heading text.
    """

    path: str
    line: int
    word: str
    reason: str
    heading: str

    def render(self) -> str:
        """Render the entry as ``file:line: word: reason (heading)``.

        Returns
        -------
        str
            The listing line.
        """
        return f"{self.path}:{self.line}: {self.word}: {self.reason} ({self.heading})"


def _prose(line: str) -> str:
    """Remove code spans and link targets from a line.

    Parameters
    ----------
    line : str
        A line outside a fenced block.

    Returns
    -------
    str
        The line without them.
    """
    return LINK_TARGET.sub("", mm.CODE_SPAN.sub(" ", line))


def lowercase_words(text: str) -> set[str]:
    """Collect the lower-case words that the prose of a document uses.

    Parameters
    ----------
    text : str
        The Markdown source.

    Returns
    -------
    set[str]
        Words of three or more letters that appear wholly in lower case, in
        lines that are not headings.
    """
    return {
        word
        for _, line in mm.unfenced_lines(text)
        if mm.HEADING.match(line) is None
        for word in LOWER_WORD.findall(_prose(line))
    }


def person_findings(path: str, text: str) -> list[Finding]:
    """Find first and second person pronouns in prose.

    Code spans, fenced blocks, blockquotes and quoted text are skipped, as are
    ``I/O`` and identifiers that contain the letter.

    Parameters
    ----------
    path : str
        The document's path.
    text : str
        Its Markdown source.

    Returns
    -------
    list[Finding]
        One finding per match, naming its line.
    """
    found: list[Finding] = []
    for number, line in mm.unfenced_lines(text):
        if line.lstrip().startswith(">"):
            continue
        for match in PERSON.finditer(QUOTED.sub(" ", _prose(line))):
            context = line.strip()[:KEY_WIDTH]
            message = f"`{match[0]}` is first or second person: {context}"
            found.append(
                Finding(path, number, PERSON_RULE, message, f"{match[0]}: {context}")
            )
    return found


def _first_word(tokens: list[str]) -> int:
    """Find the index of the heading's first word, past any section number.

    Parameters
    ----------
    tokens : list[str]
        The heading's whitespace-separated tokens.

    Returns
    -------
    int
        The index of the first token that is not a section number.
    """
    index = 0
    while index < len(tokens) - 1 and SECTION_NUMBER.match(tokens[index]):
        index += 1
    return index


def _capitalized(word: str, known: cabc.Set[str]) -> bool:
    """Say whether a word is capitalized and not exempt by its shape.

    Parameters
    ----------
    word : str
        The word without edge punctuation.
    known : collections.abc.Set[str]
        The listed proper nouns and product names.

    Returns
    -------
    bool
        ``False`` for an acronym, an identifier, a single letter, a word with
        a digit or an inner capital, and a listed term.
    """
    letters = re.sub(r"[^A-Za-z]", "", word)
    if len(letters) < MIN_LETTERS or not letters[0].isupper():
        return False
    shaped = (
        word.isupper()
        or any(c.isdigit() for c in word)
        or any(c.isupper() for c in letters[1:])
    )
    return not (shaped or word in known)


def _reason(tokens: list[str], index: int, *, quoted: bool) -> str | None:
    """Name why the case of a word cannot be decided from its place.

    Parameters
    ----------
    tokens : list[str]
        The heading's tokens.
    index : int
        The word's index.
    quoted : bool
        Whether the heading contains quotation marks.

    Returns
    -------
    str | None
        The reason, or ``None`` when the word's place decides nothing.
    """
    if tokens[index - 1].endswith(":"):
        return "after a colon"
    return "inside quotation marks" if quoted else None


def _plain(heading: str, phrases: list[str]) -> str:
    """Remove code spans, link targets and listed phrases from a heading.

    Parameters
    ----------
    heading : str
        The heading text.
    phrases : list[str]
        The listed multi-word terms, longest first.

    Returns
    -------
    str
        The heading text that the case rule reads.
    """
    plain = HEADING_LINK.sub(r"\1", mm.CODE_SPAN.sub(" ", heading))
    for phrase in phrases:
        plain = plain.replace(phrase, " ")
    return plain


def _candidates(heading: str, words: cabc.Set[str]) -> list[tuple[str, str | None]]:
    """List the capitalized words of a heading after its first word.

    Parameters
    ----------
    heading : str
        The heading text with phrases and code spans already removed.
    words : collections.abc.Set[str]
        The listed single-word terms.

    Returns
    -------
    list[tuple[str, str | None]]
        Each capitalized word with the reason its place leaves it undecided,
        or ``None``. A word followed by a number names a numbered protocol
        item, such as ``Transaction 107``, and is left out.
    """
    tokens = heading.split()
    quoted = QUOTED.sub("", heading) != heading
    found: list[tuple[str, str | None]] = []
    for index in range(_first_word(tokens) + 1, len(tokens)):
        numbered = index + 1 < len(tokens) and tokens[index + 1][:1].isdigit()
        reason = _reason(tokens, index, quoted=quoted)
        parts = (p.strip(EDGE) for p in tokens[index].split("-"))
        found += [
            (part, reason)
            for part in parts
            if _capitalized(part, words) and not numbered
        ]
    return found


def heading_findings(
    path: str,
    text: str,
    vocabulary: tuple[cabc.Set[str], cabc.Set[str]],
) -> tuple[list[Finding], list[Undecided]]:
    """Apply the sentence-case rule to the headings of one document.

    Parameters
    ----------
    path : str
        The document's path.
    text : str
        Its Markdown source.
    vocabulary : tuple[collections.abc.Set[str], collections.abc.Set[str]]
        The listed terms (single words and phrases), then the lower-case words
        of the corpus.

    Returns
    -------
    tuple[list[Finding], list[Undecided]]
        The violations, and the words that the rule cannot judge.
    """
    terms, lower = vocabulary
    phrases = sorted((t for t in terms if " " in t), key=len, reverse=True)
    words = {t for t in terms if " " not in t}
    wrong: list[Finding] = []
    undecided: list[Undecided] = []
    for section in mm.section_inventory(text):
        line = section["line_start"]
        for part, reason in _candidates(_plain(section["heading"], phrases), words):
            if reason is None and part.lower() in lower:
                message = f"`{part}` is capitalized in a sentence-case heading"
                key = f"{section['heading']}: {part}"
                wrong.append(Finding(path, line, CASE_RULE, message, key))
            else:
                reason = reason or "never written in lower case"
                undecided.append(
                    Undecided(path, line, part, reason, section["heading"])
                )
    return wrong, undecided
