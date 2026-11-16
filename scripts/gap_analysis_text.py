"""Wrap the text of the generated gap analysis report.

The renderer in ``render-protocol-gap-analysis.py`` and its report helpers
import these functions; ``tests`` and ``tools`` reach them through that script.
"""

import textwrap


def paragraph(text: str) -> str:
    """Wrap ``text`` as one Markdown paragraph of 78 columns.

    Parameters
    ----------
    text : str
        The paragraph text, without hard line breaks.

    Returns
    -------
    str
        The wrapped paragraph.
    """
    return textwrap.fill(text, width=78, break_long_words=False, break_on_hyphens=False)


def bullet(label: str, text: str) -> str:
    """Return a bold-labelled bullet whose continuation lines are indented.

    Parameters
    ----------
    label : str
        The label that opens the bullet.
    text : str
        The bullet text.

    Returns
    -------
    str
        The wrapped bullet.
    """
    return textwrap.fill(
        f"- **{label}:** {text}",
        width=78,
        subsequent_indent="  ",
        break_long_words=False,
        break_on_hyphens=False,
    )


def gap_links(identifiers: list[str]) -> str:
    """Link each gap identifier to its heading in the report.

    Parameters
    ----------
    identifiers : list[str]
        The gap identifiers, such as ``GAP-001``.

    Returns
    -------
    str
        The identifiers as comma-separated Markdown links.
    """
    return ", ".join(f"[{item}](#{item.lower()})" for item in identifiers)
