"""Pin the order of the account-batch verifier's catalogue checks.

The goldens observe only the retained corpus, so the order in which an unsound
catalogue is refused is held here, outside ``scripts/tests``, whose tests are
the golden keys. Every expectation was observed on the version of the scripts
before the verifier was split into ``verify_native_account_batch_*`` modules
(commit 8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import copy
import json
import shutil
import typing as typ
from pathlib import Path

import native_account_batch_model as model
import pytest
from verify_native_account_batches import catalogue

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-account-batch-01"
)


def drop_last(rows: list[Report]) -> None:
    """Remove the last record."""
    del rows[-1]


def snapshots() -> dict[str, dict[str, model.State]]:
    """Build the account snapshots that the verifier takes while it replays.

    Returns
    -------
    dict[str, dict[str, tuple]]
        The states after the seed, the main matrix and the distinct collision.
    """
    states = model.seed_states()
    result = {"native-seed": copy.deepcopy(states)}
    for label in model.effects():
        model.apply(states, model.effects()[label])
    result["native-final"] = copy.deepcopy(states)
    model.distinct_seed(states)
    result["native-distinct-seed"] = copy.deepcopy(states)
    model.distinct_effects(states)
    result["native-distinct-final"] = copy.deepcopy(states)
    return result


class CatalogueFixture:
    """A copy of the corpus whose catalogue records can be edited."""

    def __init__(self, directory: Path) -> None:
        """Copy the catalogue directories of the retained corpus."""
        self.directory = directory
        for phase in [
            "native-seed",
            "native-final",
            "native-distinct-seed",
            "native-distinct-final",
            "native-cleanup",
            "native-published",
        ]:
            shutil.copytree(BATCH / phase, directory / phase)

    def records(self, phase: str) -> list[Report]:
        """Read the extraction records of a phase.

        Returns
        -------
        list[dict[str, typing.Any]]
            The records.
        """
        return json.loads((self.directory / phase / "extraction.json").read_text())[
            "records"
        ]

    def write(self, phase: str, records: list[Report]) -> None:
        """Replace the extraction records of a phase."""
        path = self.directory / phase / "extraction.json"
        data = json.loads(path.read_text())
        data["records"] = records
        path.write_text(json.dumps(data))

    def edit(self, phase: str, change: cabc.Callable[[list[Report]], None]) -> None:
        """Apply ``change`` to the records of a phase and store them."""
        records = self.records(phase)
        change(records)
        self.write(phase, records)

    def user_data(self, phase: str) -> Report:
        """Find a stored account record in a phase.

        Returns
        -------
        dict[str, typing.Any]
            The first record whose path ends in ``/UserData``.
        """
        return next(r for r in self.records(phase) if r["path"].endswith("/UserData"))


def drop_seed_record(fixture: CatalogueFixture) -> None:
    """Remove one record of the seed catalogue."""
    fixture.edit("native-seed", drop_last)


def rename_seed_record(fixture: CatalogueFixture) -> None:
    """Give one seed record a path that the catalogue should not hold."""

    def change(rows: list[Report]) -> None:
        """Rename the first record."""
        rows[0]["path"] += "-x"

    fixture.edit("native-seed", change)


def change_stored_record(fixture: CatalogueFixture) -> None:
    """Change the data fork of a stored account record."""
    row = fixture.user_data("native-seed")
    (fixture.directory / "native-seed" / (row["key"] + ".data")).write_bytes(b"x")


def swap_final_identities(fixture: CatalogueFixture) -> None:
    """Swap the catalogue identities of two final records of different paths."""

    def change(rows: list[Report]) -> None:
        """Swap the first and last identities."""
        rows[0]["catalog"], rows[-1]["catalog"] = (
            rows[-1]["catalog"],
            rows[0]["catalog"],
        )

    fixture.edit("native-distinct-final", change)


def swap_seed_identities(fixture: CatalogueFixture) -> None:
    """Swap the catalogue identities of two distinct-seed records."""

    def change(rows: list[Report]) -> None:
        """Swap the identities of the two accounts that collide."""
        old = next(r for r in rows if r["path"].endswith("/m-b28-clash2-old"))
        new = next(r for r in rows if r["path"].endswith("/m-b28-clash2-new"))
        old["catalog"], new["catalog"] = new["catalog"], old["catalog"]

    fixture.edit("native-distinct-seed", change)


def drop_cleanup_record(fixture: CatalogueFixture) -> None:
    """Remove one record of the cleanup catalogue."""
    fixture.edit("native-cleanup", drop_last)


def misplace_cleanup_record(fixture: CatalogueFixture) -> None:
    """Move a cleaned-up record to a path other than the trash."""

    def change(rows: list[Report]) -> None:
        """Rename the first record."""
        rows[0]["path"] += "-x"

    fixture.edit("native-cleanup", change)


def change_cleanup_fork(fixture: CatalogueFixture) -> None:
    """Change a native fork that cleanup moved."""
    rows = fixture.records("native-cleanup")
    row = next(r for r in rows if not r["directory"])
    (fixture.directory / "native-cleanup" / (row["key"] + ".data")).write_bytes(b"x")


def change_publisher(fixture: CatalogueFixture) -> None:
    """Move the publisher's file to another path."""

    def change(rows: list[Report]) -> None:
        """Rename the record that only the published phase holds."""
        known = {r["catalog"] for r in fixture.records("native-cleanup")}
        extra = next(r for r in rows if r["catalog"] not in known)
        extra["path"] += "-x"

    fixture.edit("native-published", change)


type CatalogueBreak = cabc.Callable[[CatalogueFixture], None]

CATALOGUE: list[tuple[str, str, CatalogueBreak]] = [
    ("count", "Batch positive catalogue count differs", drop_seed_record),
    ("paths", "Batch native paths differ", rename_seed_record),
    ("stored record", "Batch stored account record differs", change_stored_record),
    (
        "identity",
        "Batch rename/delete changed original catalogue identity",
        swap_final_identities,
    ),
    (
        "collision identity",
        "Rename collision must preserve both directory identities",
        swap_seed_identities,
    ),
    ("cleanup count", "Batch positive cleanup inventory differs", drop_cleanup_record),
    ("cleanup path", "Batch cleanup path/identity differs", misplace_cleanup_record),
    ("cleanup fork", "Batch cleanup changed native fork", change_cleanup_fork),
    ("publisher", "Separate batch publisher differs", change_publisher),
]


class CatalogueOrderTests:
    """Keep the catalogue checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(CATALOGUE)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        fixture = CatalogueFixture(tmp_path)
        for _label, _message, apply in reversed(CATALOGUE[first:]):
            apply(fixture)
        _label, message, _apply = CATALOGUE[first]
        with pytest.raises(ValueError, match=message):
            catalogue(tmp_path, snapshots())
