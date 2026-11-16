"""Pin the order of the live-account verifier's storage and corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before the verifier was split into ``verify_native_live_*`` modules (commit
8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_live_accounts import storage, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-live-accounts-01"
)
STORAGE_DIRECTORIES = [
    "native-before-restart",
    "native-after-restart",
    "native-cleanup",
    "native-published",
    "native-application-before",
    "native-application-after",
]
WRONG_HASH = "0" * 64


class Fixture:
    """A copy of the storage directories whose records can be edited."""

    def __init__(self, directory: Path) -> None:
        """Copy the retained storage directories."""
        self.directory = directory
        for name in STORAGE_DIRECTORIES:
            shutil.copytree(BATCH / name, directory / name)
        shutil.copy2(
            BATCH / "restart-application-identities.json",
            directory / "restart-application-identities.json",
        )

    def records(self, phase: str) -> list[Report]:
        """Read the extraction records of a phase.

        Returns
        -------
        list[dict[str, typing.Any]]
            The records.
        """
        path = self.directory / phase / "extraction.json"
        return json.loads(path.read_text())["records"]

    def edit(self, phase: str, change: cabc.Callable[[list[Report]], None]) -> None:
        """Apply ``change`` to the records of a phase and store them."""
        path = self.directory / phase / "extraction.json"
        data = json.loads(path.read_text())
        change(data["records"])
        path.write_text(json.dumps(data))

    def fork(self, phase: str, row: Report, fork: str) -> Path:
        """Name the file that holds one fork of a record.

        Returns
        -------
        pathlib.Path
            The path of the fork file.
        """
        return self.directory / phase / (row["key"] + "." + fork)


type Break = cabc.Callable[[Fixture], None]
type Chain = list[tuple[str, str, Break]]


def drop_before(fixture: Fixture) -> None:
    """Remove a record from the pre-restart catalogue."""
    fixture.edit("native-before-restart", lambda rows: rows.__delitem__(-1))


def change_stored(fixture: Fixture) -> None:
    """Change a stored account record before the restart."""
    row = next(
        r
        for r in fixture.records("native-before-restart")
        if r["path"].endswith("/UserData")
    )
    fixture.fork("native-before-restart", row, "data").write_bytes(b"x")


def drop_after(fixture: Fixture) -> None:
    """Remove a record from the post-restart catalogue."""
    fixture.edit("native-after-restart", lambda rows: rows.__delitem__(-1))


def rename_after(fixture: Fixture) -> None:
    """Give a post-restart record another path."""

    def change(rows: list[Report]) -> None:
        """Rename the first record."""
        rows[0]["path"] += "-x"

    fixture.edit("native-after-restart", change)


def change_cleanup_fork(fixture: Fixture) -> None:
    """Change a native fork that cleanup moved."""
    rows = fixture.records("native-cleanup")
    row = next(r for r in rows if not r["directory"])
    fixture.fork("native-cleanup", row, "data").write_bytes(b"x")


def change_publisher(fixture: Fixture) -> None:
    """Move the publisher's file to another path."""
    known = {r["catalog"] for r in fixture.records("native-before-restart")}

    def change(rows: list[Report]) -> None:
        """Rename the record that the pre-restart catalogue does not hold."""
        extra = next(r for r in rows if r["catalog"] not in known)
        extra["path"] += "-x"

    fixture.edit("native-published", change)


def change_identities(fixture: Fixture) -> None:
    """Make the application identities differ before and after the restart."""
    path = fixture.directory / "restart-application-identities.json"
    data = json.loads(path.read_text())
    data["after"]["/Hotline19/Prefs"]["catalog"] = "other"
    path.write_text(json.dumps(data))


def drop_application(fixture: Fixture) -> None:
    """Remove a record from the application catalogue before the restart."""
    fixture.edit("native-application-before", lambda rows: rows.__delitem__(-1))


STORAGE: Chain = [
    ("catalogue", "Live pre-restart catalogue differs", drop_before),
    ("stored account", "Live stored account bytes differ", change_stored),
    ("identities", "Live post-restart/cleanup identities differ", drop_after),
    ("path", "Live persistence/Trash path differs", rename_after),
    ("fork", "Server restart/cleanup changed stored fork", change_cleanup_fork),
    ("publisher", "Separate live publisher differs", change_publisher),
    (
        "application forks",
        "Restart application fork identities differ",
        change_identities,
    ),
    (
        "application inventory",
        "Application metadata inventory differs",
        drop_application,
    ),
]


class StorageOrderTests:
    """Keep the storage checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(STORAGE)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        fixture = Fixture(tmp_path)
        for _label, _message, apply in reversed(STORAGE[first:]):
            apply(fixture)
        _label, message, _apply = STORAGE[first]
        with pytest.raises(ValueError, match=message):
            storage(tmp_path)


class CorpusOrderTests:
    """Keep the corpus-level checks in the order in which they have always run."""

    @staticmethod
    def copy_corpus(tmp_path: Path) -> Path:
        """Copy the retained corpus so that it can be broken.

        Returns
        -------
        pathlib.Path
            The copy.
        """
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        return directory

    @staticmethod
    def edit(directory: Path, name: str, **changes: object) -> None:
        """Replace keys of a JSON file of the corpus."""
        path = directory / name
        data = json.loads(path.read_text())
        data.update(changes)
        path.write_text(json.dumps(data))

    def test_the_epochs_precede_the_report_inventory(self, tmp_path: Path) -> None:
        """Equal server epochs are reported although the report list is wrong."""
        directory = self.copy_corpus(tmp_path)
        after = json.loads((directory / "runtime-after.json").read_text())
        self.edit(directory, "runtime-before.json", server_epoch=after["server_epoch"])
        self.edit(directory, "manifest.json", reports={})
        with pytest.raises(ValueError, match="Live runtime epochs differ"):
            verify(directory)

    def test_the_report_inventory_precedes_the_packet_reads(
        self, tmp_path: Path
    ) -> None:
        """A wrong report list is reported although the host capture is missing."""
        directory = self.copy_corpus(tmp_path)
        self.edit(directory, "manifest.json", reports={})
        (directory / "host.pcap").unlink()
        with pytest.raises(ValueError, match="Live report inventory differs"):
            verify(directory)

    def test_the_packets_are_read_before_the_recorder_count(
        self, tmp_path: Path
    ) -> None:
        """A missing guest capture is reported although the drop count is wrong."""
        directory = self.copy_corpus(tmp_path)
        (directory / "guest.pcap").unlink()
        (directory / "host-capture-statistics.txt").write_text("1 packets dropped")
        with pytest.raises(FileNotFoundError, match="guest"):
            verify(directory)

    def test_the_recorder_count_precedes_the_unread_tail(self, tmp_path: Path) -> None:
        """A wrong drop count is reported although the unread tail differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "host-capture-statistics.txt").write_text("1 packets dropped")
        (directory / "delete-unread-tails.json").write_text("{}")
        with pytest.raises(ValueError, match="recorder count/drop differs"):
            verify(directory)

    def test_the_unread_tail_precedes_the_first_plan(self, tmp_path: Path) -> None:
        """A wrong unread tail is reported although the first plan differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "delete-unread-tails.json").write_text("{}")
        self.edit(directory, "preflight/plan.json", steps=[])
        with pytest.raises(ValueError, match="Unexpected unread live socket"):
            verify(directory)

    def test_the_plan_precedes_the_capture_verification(self, tmp_path: Path) -> None:
        """A changed plan is reported before the capture's integrity is checked."""
        directory = self.copy_corpus(tmp_path)
        self.edit(directory, "preflight/plan.json", steps=[])
        with pytest.raises(ValueError, match="Live as-run plan differs"):
            verify(directory)
