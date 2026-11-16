"""Render ``docs/<set>/evidence.md``, the reverse lookup from evidence to documents.

For each document set the index lists the corpora that its documents cite, with
the family and kind that the recreation guide gives and the sections that cite
each; then the ledger identifiers and the gap identifiers that the set cites,
each with its citing sections. The output depends only on its inputs, in sorted
order, and is laid out as the Markdown formatter would lay it out, so that a
format check leaves it unchanged.
"""

import dataclasses as dc
import re
import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc

    from evidence_cites import DocCites, Occurrence
    from evidence_families import FamilyTable

INDEX_NAME = "evidence.md"
COMMAND = "python tools/check_evidence.py index --write"
UNMAPPED = "not in the recreation guide"
SEPARATOR = "<br>"
MIN_DASHES = 3
SET_DEPTH = 3
WRAP = 79
WORD = re.compile(r"`[^`]*`\S*|\S+")


@dc.dataclass(frozen=True, slots=True)
class IndexInputs:
    """What the renderer reads.

    Attributes
    ----------
    docs : collections.abc.Mapping[str, DocCites]
        The citations of each citing document, by repository-relative path.
    families : FamilyTable
        The families of the recreation guide.
    links : collections.abc.Mapping[str, str]
        The repository-relative link target of each corpus; a corpus without an
        entry is shown without a link.
    """

    docs: cabc.Mapping[str, DocCites]
    families: FamilyTable
    links: cabc.Mapping[str, str]


def set_of(path: str) -> str | None:
    """Name the document set that holds a document.

    Parameters
    ----------
    path : str
        A repository-relative POSIX path.

    Returns
    -------
    str | None
        The directory name below ``docs/``, or ``None`` for a document that is
        not inside a set directory.
    """
    parts = path.split("/")
    inside = len(parts) >= SET_DEPTH and parts[0] == "docs"
    return parts[1] if inside else None


def fill(text: str) -> list[str]:
    """Wrap prose at 80 columns without splitting a code span.

    Parameters
    ----------
    text : str
        One paragraph.

    Returns
    -------
    list[str]
        The paragraph's lines, filled greedily.
    """
    lines: list[str] = []
    current = ""
    for word in WORD.findall(text):
        if current and len(current) + 1 + len(word) > WRAP:
            lines.append(current)
            current = word
        else:
            current = f"{current} {word}" if current else word
    return [*lines, current]


def _text(value: str) -> str:
    """Make heading text safe inside link text and a table cell.

    Parameters
    ----------
    value : str
        A heading.

    Returns
    -------
    str
        The heading without pipes or square brackets.
    """
    swapped = value.replace("|", "/").replace("[", "(").replace("]", ")")
    return swapped.replace("<", "(").replace(">", ")")


def _citations(
    set_name: str,
    found: cabc.Iterable[tuple[str, Occurrence]],
    *,
    sections: bool = True,
) -> str:
    """Render the citing sections of one value.

    Parameters
    ----------
    set_name : str
        The set directory name, which is the prefix to remove from each path.
    found : collections.abc.Iterable[tuple[str, Occurrence]]
        Each citing document and the occurrence in it.
    sections : bool
        Link each citing section; otherwise link each citing document.

    Returns
    -------
    str
        Links to the distinct sections, in path and heading order.
    """
    prefix = f"docs/{set_name}/"
    targets: dict[tuple[str, str], str] = {}
    for path, occurrence in found:
        local = path.removeprefix(prefix)
        anchor = occurrence.anchor if sections else ""
        fragment = f"#{anchor}" if anchor else ""
        label = f"`{local}`"
        if anchor:
            label += f", {_text(occurrence.heading)}"
        targets[local, anchor] = f"[{label}]({local}{fragment})"
    return SEPARATOR.join(targets[key] for key in sorted(targets))


def _row(cells: list[str], widths: list[int]) -> str:
    """Lay out one table row with padded cells.

    Parameters
    ----------
    cells : list[str]
        The cell texts.
    widths : list[int]
        The width of each column.

    Returns
    -------
    str
        The row.
    """
    padded = (cell.ljust(width) for cell, width in zip(cells, widths, strict=True))
    return "| " + " | ".join(padded) + " |"


def _table(header: list[str], rows: list[list[str]], caption: str) -> list[str]:
    """Lay out a table as the formatter does, with its caption.

    Parameters
    ----------
    header : list[str]
        The column titles.
    rows : list[list[str]]
        The rows.
    caption : str
        The text after ``Table N:``, which the caller numbers.

    Returns
    -------
    list[str]
        The lines of the table, a blank line and the caption.
    """
    widths = [
        max(MIN_DASHES, *(len(row[i]) for row in [header, *rows]))
        for i in range(len(header))
    ]

    rule = "| " + " | ".join("-" * width for width in widths) + " |"
    lines = [_row(header, widths), rule, *(_row(row, widths) for row in rows)]
    return [*lines, "", caption]


def _gather(
    inputs: IndexInputs, set_name: str
) -> dict[str, dict[str, list[tuple[str, Occurrence]]]]:
    """Collect the citations of one set by kind and value.

    Parameters
    ----------
    inputs : IndexInputs
        The renderer's inputs.
    set_name : str
        The set directory name.

    Returns
    -------
    dict[str, dict[str, list[tuple[str, Occurrence]]]]
        For ``corpora``, ``ledger`` and ``gaps``, the citing occurrences of each
        value.
    """
    gathered: dict[str, dict[str, list[tuple[str, Occurrence]]]] = {
        "corpora": {},
        "ledger": {},
        "gaps": {},
    }
    for path in sorted(inputs.docs):
        if set_of(path) != set_name:
            continue
        cites = inputs.docs[path]
        for kind, occurrences in (
            ("corpora", cites.corpora),
            ("ledger", cites.ledger),
            ("gaps", cites.gaps),
        ):
            for occurrence in occurrences:
                gathered[kind].setdefault(occurrence.value, []).append((
                    path,
                    occurrence,
                ))
    return gathered


def render_index(inputs: IndexInputs, set_name: str) -> str | None:
    """Render the evidence index of one set.

    Parameters
    ----------
    inputs : IndexInputs
        The renderer's inputs.
    set_name : str
        The set directory name, such as ``protocol``.

    Returns
    -------
    str | None
        The Markdown, or ``None`` when the set's documents cite nothing.
    """
    gathered = _gather(inputs, set_name)
    if not any(gathered.values()):
        return None
    lines = [
        "# Evidence index",
        "",
        *fill(f"This file is generated by `{COMMAND}`. Do not edit it by hand."),
        "",
        *fill(
            f"It lists the evidence that the documents of the `{set_name}` set cite."
            " Each entry links to the sections or documents that cite it."
        ),
    ]
    number = 0
    corpora = gathered["corpora"]
    if corpora:
        number += 1
        rows = []
        for corpus in sorted(corpora):
            family = inputs.families.lookup(corpus)
            target = inputs.links.get(corpus)
            label = f"`{corpus}`" if target is None else f"[`{corpus}`](../../{target})"
            rows.append([
                label,
                family.label if family else UNMAPPED,
                family.kind if family else UNMAPPED,
                _citations(set_name, corpora[corpus]),
            ])
        caption = f"_Table {number}: Corpora cited by the `{set_name}` documents._"
        lines += ["", "## Corpora", ""]
        lines += _table(["Corpus", "Family", "Kind", "Cited by"], rows, caption)
    for kind, title, noun in (
        ("ledger", "Ledger identifiers", "Ledger entries"),
        ("gaps", "Gap identifiers", "Gaps"),
    ):
        values = gathered[kind]
        if not values:
            continue
        number += 1
        target = (
            "../baseline-validity-ledger.md"
            if kind == "ledger"
            else "../../gap-analysis.md"
        )
        rows = [
            [
                f"[{value}]({target}{'#' + value.lower() if kind == 'gaps' else ''})",
                _citations(set_name, values[value], sections=False),
            ]
            for value in sorted(values)
        ]
        caption = f"_Table {number}: {noun} cited by the `{set_name}` documents._"
        lines += ["", f"## {title}", ""]
        lines += _table([title.removesuffix("s"), "Cited by"], rows, caption)
    return "\n".join(lines) + "\n"


def render_indexes(inputs: IndexInputs) -> dict[str, str]:
    """Render the index of every set whose documents cite evidence.

    Parameters
    ----------
    inputs : IndexInputs
        The renderer's inputs.

    Returns
    -------
    dict[str, str]
        Content by repository-relative path ``docs/<set>/evidence.md``.
    """
    sets = sorted({name for path in inputs.docs if (name := set_of(path))})
    rendered = {name: render_index(inputs, name) for name in sets}
    return {
        f"docs/{name}/{INDEX_NAME}": text
        for name, text in rendered.items()
        if text is not None
    }
