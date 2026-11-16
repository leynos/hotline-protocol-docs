"""Check the native catalogue snapshots that the batch corpus retained.

Each phase lists the objects of the native volume; the checks tie the batch
accounts to their stored records, their paths and their identities.
"""

import json
import typing as typ

import native_account_batch_model as model
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Snapshots = dict[str, dict[str, model.State]]

HELPERS = [
    "m-b28-seed-flush",
    "m-b28-final-flush",
    "m-b28-supp-seed-flush",
    "m-b28-supp-final-flush",
]
COUNTS = {
    "native-seed": 29,
    "native-final": 54,
    "native-distinct-seed": 59,
    "native-distinct-final": 64,
}
PHASES = list(COUNTS)
CLEANUP_PHASES = [("native-cleanup", 64), ("native-published", 65)]
USERS = "/Hotline19/Users/"
FILES = "/Hotline19/Files/"
DELETED_PATHS = {"/Trash/m-b28-delete-a", "/Trash/m-b28-delete-a/UserData"}
PUBLISHED_PATH = "/Hotline19/Files/m-b28-publish"


def read_rows(base: Path) -> list[Report]:
    """Read the extraction records of one catalogue phase.

    Returns
    -------
    list[dict[str, typing.Any]]
        The records, each with a catalogue identity, a path and a key.
    """
    return json.loads((base / "extraction.json").read_text())["records"]


def expected_paths(phase: str, states: dict[str, model.State]) -> set[str]:
    """List the paths that the catalogue of ``phase`` must hold.

    Returns
    -------
    set[str]
        The user folders and their data files, any deleted account in the trash,
        and the flush helpers that the phase has created.
    """
    paths = {
        USERS + "m-b28-" + label + suffix
        for label in states
        for suffix in ["", "/UserData"]
    }
    if phase != "native-seed":
        paths |= DELETED_PATHS
    helper_count = PHASES.index(phase) + 1
    return paths | {FILES + name for name in HELPERS[:helper_count]}


def check_stored_records(
    base: Path, rows: list[Report], states: dict[str, model.State]
) -> None:
    """Check each account's stored data fork against the expected record."""
    for row in rows:
        if not row["path"].endswith("/UserData"):
            continue
        label = row["path"].split("/")[-2].removeprefix("m-b28-")
        state = states.get(label, model.seed_states().get(label))
        require(
            state is not None
            and not row["directory"]
            and (base / (row["key"] + ".data")).read_bytes()
            == model.record(label, state)
            and (base / (row["key"] + ".rsrc")).read_bytes() == b"",
            "Batch stored account record differs",
        )


def check_phase(
    directory: Path, phase: str, states: dict[str, model.State]
) -> dict[str, Report]:
    """Check one phase's inventory, paths and stored records.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The phase's records by catalogue identity.
    """
    base = directory / phase
    rows = read_rows(base)
    count = COUNTS[phase]
    require(
        len(rows) == count and len({r["catalog"] for r in rows}) == count,
        "Batch positive catalogue count differs",
    )
    records = {r["catalog"]: r for r in rows}
    require(
        {r["path"] for r in rows} == expected_paths(phase, states),
        "Batch native paths differ",
    )
    check_stored_records(base, rows, states)
    return records


def check_identities(by_phase: dict[str, dict[str, Report]]) -> dict[str, Report]:
    """Check that renames, deletions and the collision kept every identity.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The records of the last phase.
    """
    seed = by_phase["native-seed"]
    final = by_phase["native-distinct-final"]
    for identifier, original in seed.items():
        expected_path = original["path"].replace(
            "/m-b28-rename-old", "/m-b28-rename-new"
        )
        if "/m-b28-delete-a" in expected_path:
            expected_path = expected_path.replace(USERS, "/Trash/")
        require(
            identifier in final and final[identifier]["path"] == expected_path,
            "Batch rename/delete changed original catalogue identity",
        )
    for identifier, original in by_phase["native-distinct-seed"].items():
        require(
            identifier in final and final[identifier]["path"] == original["path"],
            "Rename collision must preserve both directory identities",
        )
    return final


def check_moved(
    directory: Path, final: dict[str, Report], phase: str, count: int
) -> None:
    """Check that cleanup moved every object to the trash and kept its forks."""
    base = directory / phase
    moved = {r["catalog"]: r for r in read_rows(base)}
    require(
        len(moved) == count and set(final) <= set(moved),
        "Batch positive cleanup inventory differs",
    )
    before = directory / "native-distinct-final"
    for identifier, row in final.items():
        target = moved[identifier]
        expected = row["path"].replace(USERS, "/Trash/").replace(FILES, "/Trash/")
        require(
            target["path"] == expected and target["directory"] == row["directory"],
            "Batch cleanup path/identity differs",
        )
        if not row["directory"]:
            for fork in ["data", "rsrc"]:
                require(
                    (before / (row["key"] + "." + fork)).read_bytes()
                    == (base / (target["key"] + "." + fork)).read_bytes(),
                    "Batch cleanup changed native fork",
                )
    if phase == "native-published":
        extra = moved[next(iter(set(moved) - set(final)))]
        require(extra["path"] == PUBLISHED_PATH, "Separate batch publisher differs")


def catalogue(directory: Path, snapshots: Snapshots) -> None:
    """Check every catalogue phase against the account snapshots."""
    by_phase = {
        phase: check_phase(directory, phase, states)
        for phase, states in snapshots.items()
    }
    final = check_identities(by_phase)
    for phase, count in CLEANUP_PHASES:
        check_moved(directory, final, phase, count)
