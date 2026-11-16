"""Check the gap register against its audit inputs and the evidence it cites.

``validate`` runs the checks in a fixed order and stops at the first failure,
so the message a bad register produces depends on that order. The helpers
below are called in the same order the checks always ran.
"""

import hashlib
import json
import re
import typing as typ

from gap_analysis_links import section_inventory

if typ.TYPE_CHECKING:
    from pathlib import Path

GAP_PRIORITIES = frozenset({"P0", "P1", "P2"})
GAP_KINDS = frozenset({"Missing", "Ambiguous", "Unanswered", "Evidence", "Decision"})
GAP_STATUSES = frozenset({"Open", "Investigating", "Resolved", "Deferred"})
TEXT_FIELDS = (
    "title",
    "question",
    "implementation_impact",
    "closure_criteria",
    "owner",
)
CLAIMS_PATH = "evidence/hotline-server-1.9/claims.json"
QUERIES_DIRECTORY = "evidence/hotline-server-1.9/queries"


def validate(
    root: Path, directory: Path, register: dict[str, typ.Any]
) -> dict[str, typ.Any]:
    """Validate the register against its audit inputs and return the manifest.

    Parameters
    ----------
    root : Path
        The repository root, which holds the validity ledger.
    directory : Path
        The directory that holds the register, the manifest and the snapshots.
    register : dict[str, typ.Any]
        The parsed ``gap-register.json``.

    Returns
    -------
    dict[str, typ.Any]
        The parsed audit manifest.

    Raises
    ------
    ValueError
        If any check fails.
    """
    if register["schema_version"] != 1:
        message = "Unsupported gap-register schema version"
        raise ValueError(message)
    manifest = json.loads((directory / register["source_manifest"]).read_text())
    sections = json.loads((directory / register["source_sections"]).read_text())
    check_inputs(directory, manifest, sections)
    known_sources = {
        (path, item["heading"], item["line_start"], item["line_end"])
        for path, items in sections.items()
        for item in items
    }
    ledger = json.loads((root / CLAIMS_PATH).read_text())
    ledger_ids = {item["id"] for item in ledger["claims"]}
    gaps = register["gaps"]
    identifiers = {gap["id"] for gap in gaps}
    if len(identifiers) != len(gaps):
        message = "Duplicate gap ID"
        raise ValueError(message)
    for gap in gaps:
        check_gap_fields(gap)
        check_dependencies(gap, identifiers)
        check_ledger_entries(gap, ledger_ids)
        check_sources(gap, known_sources, sections)
        check_leads(root, gap)
    check_dependency_cycles(gaps)
    check_coverage(register["review_coverage"], known_sources, identifiers)
    return manifest


def check_inputs(
    directory: Path, manifest: dict[str, typ.Any], sections: dict[str, typ.Any]
) -> None:
    """Check each audit input against its recorded hash and section inventory.

    Parameters
    ----------
    directory : Path
        The directory that holds the snapshots and the current documents.
    manifest : dict[str, typ.Any]
        The parsed audit manifest.
    sections : dict[str, typ.Any]
        The parsed section inventory, keyed by document path.

    Raises
    ------
    ValueError
        If an input changed or its section inventory differs from the source.
    """
    for item in manifest["inputs"]:
        snapshot = directory / item["snapshot"]
        expected = item["sha256"]
        for path in (snapshot, directory / item["path"]):
            if hashlib.sha256(path.read_bytes()).hexdigest() != expected:
                message = f"Audit input changed; refresh the review: {path}"
                raise ValueError(message)
        if section_inventory(snapshot.read_text()) != sections[item["path"]]:
            message = f"Section inventory differs from source: {snapshot}"
            raise ValueError(message)


def check_gap_fields(gap: dict[str, typ.Any]) -> None:
    """Check the identity and the text fields of one gap.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.
    """
    check_identity(gap)
    check_texts(gap)


def check_identity(gap: dict[str, typ.Any]) -> None:
    """Check the identifier and the enumerated fields of one gap.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.

    Raises
    ------
    ValueError
        If the identifier, priority, kind or status is invalid.
    """
    if not re.fullmatch(r"GAP-\d{3}", gap["id"]):
        message = f"Invalid gap ID: {gap['id']}"
        raise ValueError(message)
    if gap["priority"] not in GAP_PRIORITIES:
        message = f"Invalid priority: {gap['id']}"
        raise ValueError(message)
    if gap["kind"] not in GAP_KINDS:
        message = f"Invalid kind: {gap['id']}"
        raise ValueError(message)
    if gap["status"] not in GAP_STATUSES:
        message = f"Invalid status: {gap['id']}"
        raise ValueError(message)


def check_texts(gap: dict[str, typ.Any]) -> None:
    """Check that the text fields are filled and that dispositions have evidence.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.

    Raises
    ------
    ValueError
        If a text field is blank or a disposition lacks evidence.
    """
    for key in TEXT_FIELDS:
        if not gap[key].strip():
            message = f"Empty {key}: {gap['id']}"
            raise ValueError(message)
    if gap["status"] in {"Resolved", "Deferred"} and lacks_evidence(gap):
        message = f"Disposition needs evidence: {gap['id']}"
        raise ValueError(message)


def lacks_evidence(gap: dict[str, typ.Any]) -> bool:
    """Tell whether a gap has no resolution or no evidence in its resolution.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.

    Returns
    -------
    bool
        ``True`` when the resolution is missing or cites no evidence.
    """
    return not gap["resolution"] or not gap["resolution"].get("evidence")


def check_dependencies(gap: dict[str, typ.Any], identifiers: set[str]) -> None:
    """Check that a gap depends only on other registered gaps.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.
    identifiers : set[str]
        Every registered gap identifier.

    Raises
    ------
    ValueError
        If a dependency is unknown or refers to the gap itself.
    """
    if not set(gap["depends_on"]) <= identifiers - {gap["id"]}:
        message = f"Invalid dependency: {gap['id']}"
        raise ValueError(message)


def check_ledger_entries(gap: dict[str, typ.Any], ledger_ids: set[str]) -> None:
    """Check that a gap cites only entries that the validity ledger holds.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.
    ledger_ids : set[str]
        The identifiers of the validity ledger's claims.

    Raises
    ------
    ValueError
        If a related ledger entry is unknown.
    """
    if not set(gap["related_ledger_entries"]) <= ledger_ids:
        message = f"Unknown ledger entry: {gap['id']}"
        raise ValueError(message)


def check_sources(
    gap: dict[str, typ.Any],
    known_sources: set[tuple[typ.Any, ...]],
    sections: dict[str, typ.Any],
) -> None:
    """Check that each source location of a gap is a known section with its anchor.

    Parameters
    ----------
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.
    known_sources : set[tuple[typ.Any, ...]]
        The source keys of every input section.
    sections : dict[str, typ.Any]
        The parsed section inventory, keyed by document path.

    Raises
    ------
    ValueError
        If the gap has no source, or a source is unknown or has a wrong anchor.
    """
    if not gap["sources"]:
        message = f"Missing source location: {gap['id']}"
        raise ValueError(message)
    for source in gap["sources"]:
        key = (
            source["path"],
            source["heading"],
            source["line_start"],
            source["line_end"],
        )
        if key not in known_sources:
            message = f"Invalid source location: {gap['id']}"
            raise ValueError(message)
        expected = next(
            item
            for item in sections[source["path"]]
            if item["line_start"] == source["line_start"]
        )
        if source["anchor"] != expected["anchor"]:
            message = f"Invalid source anchor: {gap['id']}"
            raise ValueError(message)


def check_leads(root: Path, gap: dict[str, typ.Any]) -> None:
    """Check that each investigation lead of a gap has a query file.

    Parameters
    ----------
    root : Path
        The repository root.
    gap : dict[str, typ.Any]
        One entry of the register's ``gaps`` list.

    Raises
    ------
    ValueError
        If a lead has no query file.
    """
    for address in gap["investigation_leads"]:
        path = root / QUERIES_DIRECTORY / f"D-{address}.c"
        if not path.is_file():
            message = f"Missing investigation lead: {gap['id']} {address}"
            raise ValueError(message)


def check_dependency_cycles(gaps: list[dict[str, typ.Any]]) -> None:
    """Check that the gap dependencies form no cycle.

    Parameters
    ----------
    gaps : list[dict[str, typ.Any]]
        The register's ``gaps`` list.
    """
    graph = {item["id"]: item["depends_on"] for item in gaps}
    checked: set[str] = set()
    for identifier in graph:
        visit(graph, checked, identifier, set())


def visit(
    graph: dict[str, list[str]],
    checked: set[str],
    identifier: str,
    active: set[str],
) -> None:
    """Visit one gap and its dependencies, depth first.

    Parameters
    ----------
    graph : dict[str, list[str]]
        The dependencies of each gap.
    checked : set[str]
        The gaps whose dependencies are already known to be acyclic.
    identifier : str
        The gap to visit.
    active : set[str]
        The gaps on the path that leads to this one.

    Raises
    ------
    ValueError
        If the gap is already on the active path.
    """
    if identifier in active:
        message = f"Dependency cycle: {identifier}"
        raise ValueError(message)
    if identifier in checked:
        return
    for dependency in graph[identifier]:
        visit(graph, checked, dependency, active | {identifier})
    checked.add(identifier)


def check_coverage(
    review_coverage: list[dict[str, typ.Any]],
    known_sources: set[tuple[typ.Any, ...]],
    identifiers: set[str],
) -> None:
    """Check that the review coverage lists each input section exactly once.

    Parameters
    ----------
    review_coverage : list[dict[str, typ.Any]]
        The register's ``review_coverage`` list.
    known_sources : set[tuple[typ.Any, ...]]
        The source keys of every input section.
    identifiers : set[str]
        Every registered gap identifier.

    Raises
    ------
    ValueError
        If an entry is duplicated, unknown or references an unknown gap, or if
        the coverage misses an input section.
    """
    covered: set[tuple[typ.Any, ...]] = set()
    for item in review_coverage:
        key = (item["path"], item["heading"], item["line_start"], item["line_end"])
        if key in covered or key not in known_sources:
            message = "Invalid or duplicate review coverage entry"
            raise ValueError(message)
        covered.add(key)
        if not set(item["related_gap_ids"]) <= identifiers:
            message = "Coverage references an unknown gap"
            raise ValueError(message)
    if covered != known_sources:
        message = "The review coverage does not cover every input section"
        raise ValueError(message)
