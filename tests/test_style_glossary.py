"""Tests for the glossary obligation of the style check (INV-GLOSSARY)."""

import pytest
import style_glossary as sg
from style_helpers import GLOSSARY, TERMS


def _glossary_rules(
    glossary: str, terms: str = TERMS, extra: dict[str, str] | None = None
) -> list[str]:
    """List the key of each glossary finding for a synthetic glossary.

    Returns
    -------
    list[str]
        The keys, in order.
    """
    texts = {
        "docs/glossary.md": glossary,
        "docs/alpha/README.md": "# Alpha\n\n[glossary](../glossary.md)\n",
        **(extra or {}),
    }
    found, _ = sg.glossary_findings(texts, texts, sg.parse_terms(terms))
    return [finding.key for finding in found]


def test_a_conforming_glossary_has_no_findings() -> None:
    """The synthetic glossary meets every part of the obligation."""
    assert _glossary_rules(GLOSSARY) == [], "findings"


@pytest.mark.parametrize(
    ("glossary", "terms", "expected"),
    [
        (GLOSSARY.replace("### Alpha\n\nText.\n\n", ""), TERMS, ["term Alpha"]),
        (GLOSSARY, TERMS + "Gamma\n", ["term Gamma"]),
        (
            GLOSSARY.replace("### Alpha", "### Alpha\n\nText.\n\n### alpha"),
            TERMS,
            ["term Alpha", "anchor alpha"],
        ),
        (
            GLOSSARY.replace("### `Beta`", "### Aardvark"),
            TERMS,
            ["term Beta", "order Aardvark"],
        ),
        (
            GLOSSARY.replace("### Alpha", "### Zulu").replace("### `Beta`", "### Beta"),
            TERMS,
            ["term Alpha", "order Beta"],
        ),
    ],
)
def test_glossary_negative_controls(
    glossary: str, terms: str, expected: list[str]
) -> None:
    """A missing term, a repeat, an order fault and a repeated anchor fail."""
    assert sorted(_glossary_rules(glossary, terms)) == sorted(expected), "findings"


def test_order_is_judged_within_a_group_without_backticks_or_case() -> None:
    """Backticks and case are ignored; a new group restarts the order."""
    glossary = GLOSSARY.replace("### `Beta`", "### `beta`").replace(
        "## Labels", "## Labels\n\n### Aaa\n\nText."
    )
    assert _glossary_rules(glossary, TERMS + "Aaa\n") == [], "findings"


@pytest.mark.parametrize(
    ("doc", "expected"),
    [
        ("Packet `A1` and `A22` are defined.", []),
        ("The priority P1 is exempt.", []),
        ("Packet `D12` is undefined.", ["series D"]),
        ("Packet B7 and `B8`.", ["series B"]),
        ("Hex 0xC4, V001, GAP-001 and `abc1` match no series.", ["series V"]),
        ("See [x](B9.md) and a path.", []),
        ("```\nE5\n```\n", []),
    ],
)
def test_label_series_must_be_defined(doc: str, expected: list[str]) -> None:
    """A series letter that is neither defined nor exempt is reported once."""
    keys = _glossary_rules(GLOSSARY, extra={"docs/alpha/d.md": doc})
    assert keys == expected, "label findings"


def test_a_label_series_is_reported_once_per_document() -> None:
    """Repeated use of one undefined series gives one finding per document."""
    extra = {"docs/alpha/d.md": "D1 and D2.\n\nD3.\n", "docs/alpha/e.md": "D4\n"}
    assert _glossary_rules(GLOSSARY, extra=extra) == ["series D", "series D"], "once"


def test_each_overview_must_link_to_the_glossary() -> None:
    """A set overview without a glossary link, or absent, is reported."""
    texts = {
        "docs/glossary.md": GLOSSARY,
        "docs/alpha/README.md": "# Alpha\n",
        "docs/beta/doc.md": "# Beta\n",
    }
    found, _ = sg.glossary_findings(texts, {}, sg.parse_terms(TERMS))
    assert sorted(f.key for f in found) == ["glossary link", "overview beta"], "keys"


def test_neighbour_listing_names_documents_with_no_link() -> None:
    """A set document that links to neither its overview nor the glossary is listed."""
    texts = {
        "docs/alpha/README.md": "# A\n",
        "docs/alpha/evidence.md": "# E\n",
        "docs/alpha/one.md": "[o](README.md)\n",
        "docs/alpha/two.md": "[g](../glossary.md#x)\n",
        "docs/alpha/three.md": "[x](other.md) and [y](https://example.com/README.md)\n",
        "docs/alpha/sub/four.md": "[o](../README.md)\n",
        "docs/top.md": "# Top\n",
    }
    assert sg.unlinked_neighbours(texts) == ["docs/alpha/three.md"], "unlinked"
