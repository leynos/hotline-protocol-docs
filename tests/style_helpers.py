"""Synthetic repositories for the ``check_style`` tests."""

import typing as typ

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from tree_helpers import TreeBuilder

GLOSSARY = """# Glossary

Intro.

## Peers

### Alpha

Text.

### `Beta`

Text.

## Labels

### Packet label

Text.

| Series | Examples | Stated meaning |
| ------ | -------- | -------------- |
| A      | `A1`     | Not stated     |

_Table 1: Series._
"""
OVERVIEW = "# Alpha set\n\nSee the [glossary](../glossary.md).\n"
DOC_PATH = "docs/alpha/doc.md"
DOC = "# Alpha document\n\nA sentence about [alpha](README.md).\n"
TERMS = "Alpha\nBeta\nPacket label\nexempt-series: P priority\n"
STYLE_TERMS = "Hotline\n"
TABLE = "| a | b |\n| - | - |\n| 1 | 2 |\n"
CAPTIONED = f"{TABLE}\n_Table 1: Values._\n"
DIAGRAM = "```mermaid\nflowchart LR\n  A --> B\n```\n"
READER = "For screen readers: the flowchart joins A to B."
FIGURE = f"{READER}\n\n{DIAGRAM}\n_Figure 1: A to B._\n"


def base_tree() -> dict[str, str | bytes]:
    """Return a clean synthetic repository.

    Returns
    -------
    dict[str, str | bytes]
        Relative paths to content.
    """
    return {
        "docs/glossary.md": GLOSSARY,
        "docs/alpha/README.md": OVERVIEW,
        DOC_PATH: DOC,
        "glossary-terms.txt": TERMS,
        "style-terms.txt": STYLE_TERMS,
    }


def build(
    tmp_path: Path,
    make_tree: TreeBuilder,
    files: cabc.Mapping[str, str | bytes] | None = None,
) -> Path:
    """Write the synthetic repository, with ``files`` laid over the base.

    Parameters
    ----------
    tmp_path : pathlib.Path
        The directory to build in.
    make_tree : TreeBuilder
        The fixture that writes files.
    files : dict[str, str | bytes] | None
        Replacements and additions.

    Returns
    -------
    pathlib.Path
        The repository root.
    """
    make_tree(tmp_path, {**base_tree(), **(files or {})})
    return tmp_path
