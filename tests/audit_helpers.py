"""Build a small audit world for the refresh tests.

The world mirrors the real layout: a register checkout beside a ``mothra``
checkout that holds revision 1 of the audit under
``evidence/protocol-gap-analysis``.
"""

import dataclasses as dc
import datetime as dt
import hashlib
import json
import typing as typ

import markdown_model as mm
from git_helpers import init_repo

if typ.TYPE_CHECKING:
    from pathlib import Path

ALPHA = "# Alpha\n\nintro\n\n## Beta\n\ntext\n"
GAMMA = "# Gamma\n\ntext\n\n## Delta\n\nmore\n"
DOCS = {"a.md": ALPHA, "b.md": GAMMA}
PREVIOUS_DAY = "2026-11-14"
TODAY = dt.date(2026, 11, 15)
NOW = dt.datetime(2026, 11, 15, 9, 30, tzinfo=dt.UTC)
GAP_FIELDS = ("question", "implementation_impact", "closure_criteria")


@dc.dataclass(frozen=True, slots=True)
class World:
    """Where the pieces of a test audit live.

    Attributes
    ----------
    root : pathlib.Path
        The register checkout (``hotline-protocol-docs`` in the real layout).
    evidence : pathlib.Path
        The sibling checkout's ``evidence`` directory.
    """

    root: Path
    evidence: Path

    @property
    def register(self) -> Path:
        """The register file."""
        return self.root / "gap-register.json"


def _location(path: str, section: mm.Section) -> dict[str, object]:
    """Describe a section as the register records it.

    Parameters
    ----------
    path : str
        The document path.
    section : mm.Section
        The section.

    Returns
    -------
    dict[str, object]
        The location keys, in the register's key order.
    """
    return {
        "path": path,
        "heading": section["heading"],
        "level": section["level"],
        "line_start": section["line_start"],
        "anchor": section["anchor"],
        "line_end": section["line_end"],
    }


def _gap(number: int, sources: list[dict[str, object]]) -> dict[str, object]:
    """Build one gap with every field the oracle reads.

    Parameters
    ----------
    number : int
        The gap number.
    sources : list[dict[str, object]]
        Its source locations.

    Returns
    -------
    dict[str, object]
        The gap.
    """
    return {
        "id": f"GAP-{number:03d}",
        "area": "Area",
        "priority": "P1",
        "kind": "Missing",
        "status": "Open",
        "owner": "Unassigned",
        "title": f"Title {number}",
        "sources": sources,
        "question": f"Question {number}?",
        "implementation_impact": "Impact.",
        "closure_criteria": f"Close {number} when ready.",
        "related_ledger_entries": [],
        "investigation_leads": [],
        "depends_on": [],
        "resolution": None,
    }


def build_world(base: Path) -> World:
    """Create the register checkout, revision 1 and the two-gap register.

    Parameters
    ----------
    base : pathlib.Path
        An empty directory.

    Returns
    -------
    World
        The created layout; the register checkout is a committed Git repository.
    """
    root, evidence = base / "hotline-protocol-docs", base / "mothra" / "evidence"
    directory = evidence / "protocol-gap-analysis" / PREVIOUS_DAY / "revision-1"
    (directory / "inputs").mkdir(parents=True)
    root.mkdir(parents=True)
    inventory: dict[str, list[mm.Section]] = {}
    inputs: list[dict[str, object]] = []
    for name, text in DOCS.items():
        (root / name).write_text(text, encoding="utf-8")
        snapshot = directory / "inputs" / f"{name}.txt"
        snapshot.write_text(text, encoding="utf-8")
        inventory[name] = mm.section_inventory(text)
        digest = hashlib.sha256(text.encode()).hexdigest()
        relative = f"../mothra/evidence/protocol-gap-analysis/{PREVIOUS_DAY}/revision-1"
        inputs.append({
            "path": name,
            "snapshot": f"{relative}/inputs/{name}.txt",
            "sha256": digest,
            "lines": len(text.splitlines()),
        })
    manifest = {
        "captured_at_utc": "2026-11-14T01:00:00+00:00",
        "source_git_head": "0" * 40,
        "source_worktree_status": "",
        "inputs": inputs,
        "method": "Original method text.",
        "updated_at_utc": "2026-11-14T01:00:00+00:00",
        "independent_review": {"scope": "carried forward unchanged"},
    }
    write_json(directory / "manifest.json", manifest)
    write_json(directory / "sections.json", inventory)
    write_json(root / "gap-register.json", _register(inventory))
    init_repo(root)
    return World(root, evidence)


def _register(inventory: dict[str, list[mm.Section]]) -> dict[str, object]:
    """Build the register for the two-document inventory.

    Parameters
    ----------
    inventory : dict[str, list[mm.Section]]
        Revision 1's sections.

    Returns
    -------
    dict[str, object]
        A register with two gaps and a coverage entry for every section.
    """
    a, b = inventory["a.md"], inventory["b.md"]
    gaps = [
        _gap(1, [_location("a.md", a[0])]),
        _gap(2, [_location("a.md", a[1]), _location("b.md", b[0])]),
    ]
    coverage = [
        {
            **_location(path, section),
            "review": "Reviewed",
            "direct_gap_ids": ["GAP-001"],
            "related_gap_ids": ["GAP-001", "GAP-002"],
        }
        for path, sections in inventory.items()
        for section in sections
    ]
    return {
        "schema_version": 1,
        "title": "Test register",
        "audited_at_utc": "2026-11-12T00:00:00+00:00",
        "last_updated": PREVIOUS_DAY,
        "source_manifest": (
            f"../mothra/evidence/protocol-gap-analysis/{PREVIOUS_DAY}/"
            "revision-1/manifest.json"
        ),
        "source_sections": (
            f"../mothra/evidence/protocol-gap-analysis/{PREVIOUS_DAY}/"
            "revision-1/sections.json"
        ),
        "validity_ledger": "../mothra/docs/ledger.md",
        "binary_sha256": "0" * 64,
        "method": "Test.",
        "gaps": gaps,
        "review_coverage": coverage,
    }


def write_json(path: Path, value: object) -> None:
    """Write ``value`` in the canonical layout.

    Parameters
    ----------
    path : pathlib.Path
        The file to write.
    value : object
        A JSON-serializable value.
    """
    path.write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", "utf-8")


def read_json(path: Path) -> dict[str, typ.Any]:
    """Read a JSON file.

    Parameters
    ----------
    path : pathlib.Path
        The file to read.

    Returns
    -------
    dict[str, typing.Any]
        The parsed object.
    """
    return json.loads(path.read_text(encoding="utf-8"))
