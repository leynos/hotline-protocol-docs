"""Check the catalogue identities and the physical forks of the move corpus.

verify_native_moves imports catalogue from this module and keeps it importable.
"""

import json
import typing as typ

from native_move_cases import ROOT, move_specs
from verify_native_core import require
from verify_native_moves_checks import FAILED_MOVES

if typ.TYPE_CHECKING:
    from pathlib import Path

__all__ = ["catalogue"]

type Report = dict[str, typ.Any]
type Stage = dict[str, Report]

POSITIVE_SEEDED = 72
POSITIVE_FINAL = 73
POSITIVE_CLEANUP = 70
# The resource fork of the alias after its target moves to Trash, in bytes.
ALIAS_RESOURCE_BYTES = 554
FILES_PREFIX = "/Hotline19/Files/"
# The subtree that the corpus owns, under the Files root.
OWNED_PREFIX = FILES_PREFIX + ROOT.decode()
ALIAS_PATH = OWNED_PREFIX + "/del-alias"


def _load_stages(directory: Path) -> tuple[Stage, Stage, Stage]:
    """Load the seeded, final and cleanup catalogue records, keyed by identity.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    tuple[dict[str, dict], dict[str, dict], dict[str, dict]]
        The seeded, final and cleanup records, each keyed by catalogue identity.
    """
    stages = {}
    for stage, count in [
        ("native-seeded", POSITIVE_SEEDED),
        ("native-final", POSITIVE_FINAL),
        ("native-cleanup", POSITIVE_CLEANUP),
    ]:
        rows = json.loads((directory / stage / "extraction.json").read_text())[
            "records"
        ]
        require(len(rows) == count, "Positive catalogue inventory differs")
        stages[stage] = {r["catalog"]: r for r in rows}
    before, after, cleaned = (
        stages[s] for s in ["native-seeded", "native-final", "native-cleanup"]
    )
    require(
        set(before) <= set(after) and len(set(after) - set(before)) == 1,
        "Move/delete lost seeded catalogue identity",
    )
    return before, after, cleaned


def _expected_changes() -> list[tuple[str, str]]:
    """List the path changes that each owned move and deletion makes.

    Returns
    -------
    list[tuple[str, str]]
        Each old path and the new path that replaces it, in their checked order.
    """
    changes = []
    for spec in move_specs():
        if spec["label"] in FAILED_MOVES | {"same-parent"}:
            continue
        name = bytes.fromhex(spec["name_hex"]).decode()
        old = OWNED_PREFIX + "/S/" + name
        new = (
            FILES_PREFIX + name
            if spec["label"].startswith("destination-")
            else OWNED_PREFIX + "/D/" + name
        )
        changes.append((old, new))
    changes += [
        (OWNED_PREFIX + "/del-file", "/Trash/del-file"),
        (OWNED_PREFIX + "/del-nonempty", "/Trash/del-nonempty"),
        (OWNED_PREFIX + "/del-path-only", "/Trash/del-path-only"),
        (OWNED_PREFIX + "/del-c1/m-del22-dupe", "/Trash/m-del22-dupe"),
        (OWNED_PREFIX + "/del-c2/m-del22-dupe", "/Trash/m-del22-dupe1"),
        (OWNED_PREFIX + "/del-alias-target", "/Trash/del-alias-target"),
    ]
    return changes


def _moved_path(path: str, changes: list[tuple[str, str]]) -> str:
    """Map a seeded path through the first change that covers it.

    Parameters
    ----------
    path : str
        The seeded path of a catalogue record.
    changes : list[tuple[str, str]]
        The changes from ``_expected_changes``.

    Returns
    -------
    str
        The path after the first matching change, or the path itself.
    """
    expected = path
    for old, new in changes:
        if expected == old or expected.startswith(old + "/"):
            expected = new + expected[len(old) :]
            break
    return expected


def _check_forks(directory: Path, row: Report, current: Report) -> None:
    """Check that the data and resource forks of a file kept their bytes.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    row : dict[str, typing.Any]
        The seeded record of the file.
    current : dict[str, typing.Any]
        The final record of the same file.
    """
    for fork in ["data", "rsrc"]:
        seeded = (directory / "native-seeded" / (row["key"] + "." + fork)).read_bytes()
        final = (
            directory / "native-final" / (current["key"] + "." + fork)
        ).read_bytes()
        if row["path"] == ALIAS_PATH and fork == "rsrc":
            require(
                seeded != final and len(seeded) == len(final) == ALIAS_RESOURCE_BYTES,
                "Alias resource refresh after target Trash move differs",
            )
        else:
            require(seeded == final, "Move/delete changed physical data/resource fork")


def _check_moved_rows(
    directory: Path, before: Stage, after: Stage, changes: list[tuple[str, str]]
) -> None:
    """Check the path and forks of every seeded record after the moves.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    before : dict[str, dict[str, typing.Any]]
        The seeded records, keyed by catalogue identity.
    after : dict[str, dict[str, typing.Any]]
        The final records, keyed by catalogue identity.
    changes : list[tuple[str, str]]
        The path changes from ``_expected_changes``.
    """
    for identifier, row in before.items():
        expected = _moved_path(row["path"], changes)
        require(
            after[identifier]["path"] == expected,
            "Move/Trash catalogue path or child identity differs",
        )
        if row["directory"]:
            continue
        _check_forks(directory, row, after[identifier])


def _check_cleanup_observations(cleaned: Stage, after: Stage) -> None:
    """Check that the partial cleanup observations are Trash objects in the inventory.

    Parameters
    ----------
    cleaned : dict[str, dict[str, typing.Any]]
        The cleanup records, keyed by catalogue identity.
    after : dict[str, dict[str, typing.Any]]
        The final records, keyed by catalogue identity.
    """
    require(
        set(cleaned) <= set(after)
        and all(r["path"].startswith("/Trash/") for r in cleaned.values()),
        "Partial cleanup observations do not identify Trash objects",
    )
    missing = {after[i]["path"] for i in set(after) - set(cleaned)}
    require(
        missing == {"/Hotline19/Files/m-mv22-f" + n for n in ["08", "09", "10"]},
        "Unobserved cleanup inventory differs",
    )


def _check_cleaned_paths(cleaned: Stage, after: Stage) -> None:
    """Check the path of every cleanup record against the subtree it came from.

    Parameters
    ----------
    cleaned : dict[str, dict[str, typing.Any]]
        The cleanup records, keyed by catalogue identity.
    after : dict[str, dict[str, typing.Any]]
        The final records, keyed by catalogue identity.
    """
    for identifier, row in cleaned.items():
        prior = after[identifier]
        expected = prior["path"]
        if expected.startswith(OWNED_PREFIX):
            expected = "/Trash/" + ROOT.decode() + expected[len(OWNED_PREFIX) :]
        elif expected.startswith(FILES_PREFIX):
            expected = "/Trash/" + expected.removeprefix(FILES_PREFIX)
        require(
            row["path"] == expected, "Owned cleanup changed subtree path or identity"
        )


def _check_collisions(directory: Path, original: Stage, after: Stage) -> None:
    """Check that a collision in Trash preserves both separately identified children.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    original : dict[str, dict[str, typing.Any]]
        The seeded records, keyed by their path.
    after : dict[str, dict[str, typing.Any]]
        The final records, keyed by catalogue identity.
    """
    for source in [
        OWNED_PREFIX + "/del-c1/m-del22-dupe",
        OWNED_PREFIX + "/del-c2/m-del22-dupe",
    ]:
        row = original[source]
        data = (
            directory / "native-final" / (after[row["catalog"]]["key"] + ".data")
        ).read_bytes()
        require(
            data == b"delete-child-" + source.split("/")[-2].encode(),
            "Trash collision lost distinct source bytes",
        )


def catalogue(directory: Path) -> dict[str, typ.Any]:
    """Check the catalogue of the move corpus and summarise its positive counts.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory, with the seeded, final and cleanup extractions.

    Returns
    -------
    dict[str, typing.Any]
        The positive counts, the identity result and the coverage that remains partial.
    """
    before, after, cleaned = _load_stages(directory)
    original = {r["path"]: r for r in before.values()}
    changes = _expected_changes()
    _check_moved_rows(directory, before, after, changes)
    _check_cleanup_observations(cleaned, after)
    _check_cleaned_paths(cleaned, after)
    _check_collisions(directory, original, after)
    return {
        "positive_seeded": POSITIVE_SEEDED,
        "positive_final": POSITIVE_FINAL,
        "positive_cleanup": POSITIVE_CLEANUP,
        "all_seeded_identities_retained_before_cleanup": True,
        "cleanup_disk_coverage": "Partial: three root file markers lack positive "
        "post-move probes",
    }
