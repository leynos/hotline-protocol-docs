"""Synthetic repositories for the ``check_evidence`` tests."""

import json
import typing as typ

import check_evidence

if typ.TYPE_CHECKING:
    from pathlib import Path

    from tree_helpers import TreeBuilder

CORPUS = "evidence/gap-remediation/2026-11-12/batch-01"
OTHER = "evidence/gap-remediation/2026-11-13/native-banner-01"
GUIDE = f"""# Recreating evidence

## 11. Corpus families

| Family | Kind | Included | Corpora | Described by | Recreate |
| --- | --- | ---: | --- | --- | --- |
| F2 Static query batches | Queries | 2 | `{CORPUS}` to `batch-02` | Ledger | 9 |
| F10 Native capture | Native execution | 1 | See [Table 3](#families) | The guide | 4 |

_Table 5: Families._

## 4. Native captures

| Family | Included corpora | Planner |
| --- | --- | --- |
| Banners | 11-13 `native-banner-01` | `scripts/tool.py` |

_Table 3: Native families._
"""
LEDGER = """# Remaining evidence work

| Gap | Priority |
| --- | --- |
| [GAP-002](../../gap-analysis.md#gap-002) | P1 |
| [GAP-003](../../gap-analysis.md#gap-003) | P2 |

_Table 1: Gaps._
"""
DOC_PATH = "docs/alpha/doc.md"
NOTE = "\n> Status note (2026-11-16): the register lists GAP-001 as Resolved.\n"
DOC = f"""# Alpha document

## Section one

The corpus is [here](../../{CORPUS}/manifest.json) and the entry V001 holds.
GAP-001 is Resolved and GAP-002 remains open. Run `scripts/tool.py` to replay.
"""


def base_tree() -> dict[str, str | bytes]:
    """Return a clean repository, without generated indexes.

    Returns
    -------
    dict[str, str | bytes]
        Relative paths to content.
    """
    register = {
        "gaps": [
            {"id": "GAP-001", "status": "Resolved"},
            {"id": "GAP-002", "status": "Investigating"},
            {"id": "GAP-003", "status": "Open"},
        ]
    }
    claims = {"claims": [{"id": "V001"}, {"id": "M001"}]}
    return {
        "gap-register.json": json.dumps(register),
        "evidence/hotline-server-1.9/claims.json": json.dumps(claims),
        f"{CORPUS}/manifest.json": "{}",
        f"{OTHER}/manifest.json": "{}",
        "scripts/tool.py": "",
        "docs/native-evidence/README.md": "# Native evidence\n",
        "docs/native-evidence/recreating-evidence.md": GUIDE,
        "docs/provenance/README.md": "# Provenance\n",
        "docs/provenance/remaining-evidence-work.md": LEDGER,
        "docs/alpha/README.md": "# Alpha\n",
        "docs/alpha/doc.md": DOC,
    }


def build(
    root: Path,
    make_tree: TreeBuilder,
    changes: dict[str, str | bytes] | None = None,
    after: dict[str, str | bytes] | None = None,
) -> Path:
    """Write a repository, generate its indexes, then apply ``after``.

    Parameters
    ----------
    root : pathlib.Path
        The directory to fill.
    make_tree : TreeBuilder
        The tree-writing fixture.
    changes : dict[str, str | bytes] | None
        Files to add or replace before the indexes are generated.
    after : dict[str, str | bytes] | None
        Files to add or replace after, which can make an index stale.

    Returns
    -------
    pathlib.Path
        ``root``.
    """
    make_tree(root, {**base_tree(), **(changes or {})})
    check_evidence.write_indexes(root)
    make_tree(root, after or {})
    return root


def rules(result: check_evidence.Result) -> list[tuple[str, str]]:
    """List the ``(rule, key)`` of each finding.

    Parameters
    ----------
    result : check_evidence.Result
        A run's result.

    Returns
    -------
    list[tuple[str, str]]
        One pair per finding, in report order.
    """
    return [(f.rule, f.key) for f in result.findings]


def doc_with(*paragraphs: str) -> dict[str, str | bytes]:
    """Replace the alpha document with the given paragraphs.

    Returns
    -------
    dict[str, str | bytes]
        A change set for :func:`build`.
    """
    body = "\n\n".join(paragraphs)
    return {DOC_PATH: f"# Alpha\n\n## Section one\n\n{body}\n"}
