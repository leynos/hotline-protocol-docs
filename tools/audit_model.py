"""The pure part of the audit refresh: section correspondence and the register.

A refreshed audit revision must describe the same gaps against the current
documents. The only legitimate drift in a gap's sources is where its sections
sit. This module decides, without touching the file system, which new section
each old section becomes, and rewrites the register's locations accordingly.

Correspondence rules. A document whose heading count and anchor sequence are
unchanged maps its n-th old section to its n-th new section; case-only heading
edits are therefore harmless because the anchor is lowercased. Anything else
needs a section map: a JSON object with an optional ``files`` object (old path
to new path, for relocated documents) and an optional ``sections`` list of
``{"old": [path, ordinal], "new": [path, ordinal]}`` entries. Ordinals count
from one. Several old sections may map to one new section. A document with any
explicit entry is *restructured*: every one of its sections must then be mapped
explicitly.
"""

import copy
import typing as typ

import markdown_model as mm
from section_map import Location, RefreshRefusedError, SectionMap

type Inventory = dict[str, list[mm.Section]]
type Register = dict[str, typ.Any]

PROTECTED_FIELDS = (
    "id",
    "status",
    "question",
    "closure_criteria",
    "priority",
    "kind",
    "depends_on",
)
GAP_LISTS = ("direct_gap_ids", "related_gap_ids")


def _correspond(path: str, old: list[mm.Section], new: list[mm.Section]) -> None:
    """Insist that two section lists share a heading count and anchor sequence.

    Parameters
    ----------
    path : str
        The document, for the message.
    old : list[mm.Section]
        The previous sections.
    new : list[mm.Section]
        The current sections.

    Raises
    ------
    RefreshRefusedError
        If a heading was added, removed, renamed or reordered.
    """
    old_anchors = [s["anchor"] for s in old]
    new_anchors = [s["anchor"] for s in new]
    if old_anchors == new_anchors:
        return
    if len(old_anchors) != len(new_anchors):
        what = f"{len(old_anchors)} headings became {len(new_anchors)}"
    else:
        pairs = zip(old_anchors, new_anchors, strict=True)
        index = next(i for i, (was, now) in enumerate(pairs) if was != now)
        was, now = old_anchors[index], new_anchors[index]
        what = f"heading {index + 1} changed from #{was} to #{now}"
    message = f"{path}: {what}; add section-map entries to refresh it"
    raise RefreshRefusedError(message)


def _map_document(
    path: str, old: list[mm.Section], new: Inventory, smap: SectionMap
) -> dict[Location, Location]:
    """Map every section of one old document.

    Parameters
    ----------
    path : str
        The old document path.
    old : list[mm.Section]
        Its previous sections.
    new : dict[str, list[mm.Section]]
        The current inventory.
    smap : SectionMap
        The reviewed map.

    Returns
    -------
    dict[tuple[str, int], tuple[str, int]]
        New location per old location.

    Raises
    ------
    RefreshRefusedError
        If the document is restructured but not fully mapped, or has no
        current counterpart.
    """
    explicit = {(path, i): smap.sections.get((path, i)) for i in range(1, len(old) + 1)}
    if any(target for target in explicit.values()):
        missing = [i for (_, i), target in explicit.items() if target is None]
        if missing:
            message = f"{path}: restructured, but sections {missing} have no map entry"
            raise RefreshRefusedError(message)
        return {key: target for key, target in explicit.items() if target}
    target_path = smap.files.get(path, path)
    if target_path not in new:
        message = f"{path}: no current document {target_path} and no map entry"
        raise RefreshRefusedError(message)
    _correspond(path, old, new[target_path])
    return {(path, i): (target_path, i) for i in range(1, len(old) + 1)}


def build_mapping(
    old: Inventory, new: Inventory, smap: SectionMap
) -> dict[Location, Location]:
    """Decide which new section each old section becomes.

    Parameters
    ----------
    old : dict[str, list[mm.Section]]
        The previous revision's sections.
    new : dict[str, list[mm.Section]]
        The current sections of every input.
    smap : SectionMap
        The reviewed map for moved and restructured documents.

    Returns
    -------
    dict[tuple[str, int], tuple[str, int]]
        New ``(path, ordinal)`` per old ``(path, ordinal)``.

    Raises
    ------
    RefreshRefusedError
        If a correspondence is illegal, a mapped target does not exist, or a
        current section is left without an old counterpart.
    """
    mapping: dict[Location, Location] = {}
    for path, sections in old.items():
        mapping.update(_map_document(path, sections, new, smap))
    parts = [(key, part) for key in mapping for part in smap.also.get(key, ())]
    for old_key, (path, ordinal) in [*mapping.items(), *parts]:
        if ordinal > len(new.get(path, [])):
            message = (
                f"{old_key[0]} section {old_key[1]} maps to missing "
                f"{path} section {ordinal}"
            )
            raise RefreshRefusedError(message)
    targets = {*mapping.values(), *(part for _, part in parts)}
    for path, sections in new.items():
        orphans = [i for i in range(1, len(sections) + 1) if (path, i) not in targets]
        if orphans:
            message = f"{path}: sections {orphans} have no old counterpart in the map"
            raise RefreshRefusedError(message)
    return mapping


def _old_ordinal(path: str, item: dict[str, typ.Any], old: Inventory) -> int:
    """Find which old section a register location names.

    Parameters
    ----------
    path : str
        The document path recorded in the location.
    item : dict[str, typing.Any]
        The location (a source or a coverage entry).
    old : dict[str, list[mm.Section]]
        The previous inventory.

    Returns
    -------
    int
        The one-based ordinal of the matching section.

    Raises
    ------
    RefreshRefusedError
        If no previous section matches.
    """
    for ordinal, section in enumerate(old.get(path, []), 1):
        if (section["heading"], section["line_start"], section["line_end"]) == (
            item["heading"],
            item["line_start"],
            item["line_end"],
        ):
            return ordinal
    message = f"{path}: register names a section absent from the previous revision"
    raise RefreshRefusedError(message)


def _relocate(item: dict[str, typ.Any], target: Location, new: Inventory) -> None:
    """Overwrite a location's keys from the new section, keeping key order.

    Parameters
    ----------
    item : dict[str, typing.Any]
        The source or coverage entry, changed in place.
    target : tuple[str, int]
        The new path and ordinal.
    new : dict[str, list[mm.Section]]
        The current inventory.
    """
    path, ordinal = target
    section = new[path][ordinal - 1]
    item["path"] = path
    item["heading"] = section["heading"]
    item["level"] = section["level"]
    item["line_start"] = section["line_start"]
    item["line_end"] = section["line_end"]
    item["anchor"] = section["anchor"]


def _merge(into: dict[str, typ.Any], other: dict[str, typ.Any]) -> None:
    """Union the gap-id lists of two coverage entries, keeping first-seen order.

    Parameters
    ----------
    into : dict[str, typing.Any]
        The surviving entry, changed in place.
    other : dict[str, typing.Any]
        The entry that merges into it.
    """
    for key in GAP_LISTS:
        if key in other:
            into[key] = list(dict.fromkeys([*into.get(key, []), *other[key]]))


def with_parts(
    mapping: dict[Location, Location], smap: SectionMap
) -> dict[Location, tuple[Location, ...]]:
    """List every new section that each old section became.

    Parameters
    ----------
    mapping : dict[tuple[str, int], tuple[str, int]]
        The old-to-new section correspondence from :func:`build_mapping`.
    smap : SectionMap
        The reviewed map, whose ``also`` entries name the further parts of a
        split section.

    Returns
    -------
    dict[tuple[str, int], tuple[tuple[str, int], ...]]
        The primary new section first, then any further parts.
    """
    return {key: (target, *smap.also.get(key, ())) for key, target in mapping.items()}


def rewrite_register(
    register: Register,
    old: Inventory,
    new: Inventory,
    mapping: dict[Location, tuple[Location, ...]],
) -> Register:
    """Return a copy of the register with its locations moved to the new inventory.

    Parameters
    ----------
    register : dict[str, typing.Any]
        The current register.
    old : dict[str, list[mm.Section]]
        The previous inventory its locations refer to.
    new : dict[str, list[mm.Section]]
        The current inventory.
    mapping : dict[tuple[str, int], tuple[tuple[str, int], ...]]
        The new sections each old section became (see :func:`with_parts`). Gap
        sources follow the first; every one receives the review coverage.

    Returns
    -------
    dict[str, typing.Any]
        The rewritten register; only ``sources`` and ``review_coverage`` differ.
    """
    result = copy.deepcopy(register)
    for gap in result["gaps"]:
        moved: dict[Location, dict[str, typ.Any]] = {}
        for source in gap["sources"]:
            key = (source["path"], _old_ordinal(source["path"], source, old))
            target = mapping[key][0]
            _relocate(source, target, new)
            moved.setdefault(target, source)
        gap["sources"] = list(moved.values())
    merged: dict[Location, dict[str, typ.Any]] = {}
    for entry in result["review_coverage"]:
        key = (entry["path"], _old_ordinal(entry["path"], entry, old))
        for target in mapping[key]:
            placed = copy.deepcopy(entry)
            _relocate(placed, target, new)
            if target in merged:
                _merge(merged[target], placed)
            else:
                merged[target] = placed
    result["review_coverage"] = list(merged.values())
    return result


def compare_registers(old: Register, new: Register) -> list[str]:
    """List every change to a protected field, or to the set of gaps.

    Parameters
    ----------
    old : dict[str, typing.Any]
        The reference register.
    new : dict[str, typing.Any]
        The register under test.

    Returns
    -------
    list[str]
        One message per changed protected field and per added or removed gap;
        empty when the registers agree on everything protected.
    """
    found: list[str] = []
    before = {gap["id"]: gap for gap in old["gaps"]}
    after = {gap["id"]: gap for gap in new["gaps"]}
    found += [f"{name}: gap was removed" for name in before if name not in after]
    found += [f"{name}: gap was added" for name in after if name not in before]
    for name in (name for name in before if name in after):
        found += [
            f"{name}: protected field {field} changed"
            for field in PROTECTED_FIELDS
            if before[name].get(field) != after[name].get(field)
        ]
    return found
