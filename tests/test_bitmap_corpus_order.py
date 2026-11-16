"""Pin the order of the bitmap verifier's corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. The packet records are not read: the tests replace the readers and
the per-capture checks of the module with stubs, so each expectation is about
the order in which ``verify`` makes its own checks. Every expectation was
observed on the version of the scripts before the verifier was split into
``verify_native_bitmap_checks`` (commit 0b34126).

A corpus that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import dataclasses as dc
import json
import typing as typ
from pathlib import Path

import pytest
import verify_native_bitmaps as module

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-bitmaps-01"
)
HOST_PACKETS = 582
WRONG_SHA = "0" * 64
WRONG_ERROR = 1
EXTRA = {"paired": 0}


def stub_packets(_path: Path) -> list[None]:
    """Stand in for the packet reader.

    Returns
    -------
    list[None]
        As many records as the host capture of the corpus holds.
    """
    return [None] * HOST_PACKETS


def stub_reconcile(*_args: object, **kwargs: dict[str, bytes]) -> list[int]:
    """Stand in for the packet reconciliation.

    Returns
    -------
    list[int]
        One observation for each connection, as the retained corpus pairs them.
    """
    return [0] * (EXTRA["paired"] + (2 if kwargs["unread_output"] else 1))


def stub_capture(path: Path) -> Report:
    """Stand in for the capture replay.

    Returns
    -------
    dict[str, typing.Any]
        The report that the replay would have returned.
    """
    return json.loads((path / "report.json").read_text())


@dc.dataclass(slots=True)
class Staged:
    """A mirror of the corpus whose files can be replaced one by one."""

    root: Path
    manifest: Report

    @classmethod
    def build(cls, root: Path) -> typ.Self:
        """Mirror the corpus with a symbolic link for each of its entries.

        Returns
        -------
        Staged
            The mirror, which ``verify`` accepts while the readers are stubs.
        """
        for child in CORPUS.iterdir():
            (root / child.name).symlink_to(child)
        manifest = json.loads((CORPUS / "manifest.json").read_text())
        (root / "manifest.json").unlink()
        return cls(root, manifest)

    def thaw(self, relative: str) -> Path:
        """Make one file of the mirror a real file that can be changed.

        Returns
        -------
        pathlib.Path
            The file's path in the mirror.
        """
        current = self.root
        parts = Path(relative).parts
        for part in parts[:-1]:
            current /= part
            if current.is_symlink():
                target = current.resolve()
                current.unlink()
                current.mkdir()
                for child in target.iterdir():
                    (current / child.name).symlink_to(child)
        leaf = current / parts[-1]
        if leaf.is_symlink():
            content = leaf.read_bytes()
            leaf.unlink()
            leaf.write_bytes(content)
        return leaf

    def edit(self, relative: str, change: cabc.Callable[[typ.Any], None]) -> None:
        """Change the JSON in one file of the mirror."""
        path = self.thaw(relative)
        value = json.loads(path.read_text())
        change(value)
        path.write_text(json.dumps(value))

    def verify(self) -> None:
        """Verify the mirror."""
        (self.root / "manifest.json").write_text(json.dumps(self.manifest))
        module.verify(self.root)


type Break = cabc.Callable[[Staged], None]


def fewer_reports(staged: Staged) -> None:
    """Leave one report out of the inventory."""
    staged.manifest["reports"].pop()


def other_runtime(staged: Staged) -> None:
    """Name another emulator process."""
    staged.edit("runtime.json", lambda r: r.update(emulator_pid=1))


def dropped_packets(staged: Staged) -> None:
    """Record that the kernel dropped packets."""
    path = staged.thaw("host-capture-statistics.txt")
    path.write_text(path.read_text().replace("0 packets dropped", "1 packets dropped"))


def extra_tails(staged: Staged) -> None:
    """Add a suite to the unread tails."""
    staged.edit("unread-tails.json", lambda t: t.update(other={}))


def other_driver(staged: Staged) -> None:
    """Name another driver in the manifest."""
    staged.manifest["driver_sha256"] = WRONG_SHA


def other_tail(staged: Staged) -> None:
    """Give the guest another unread tail than the host."""

    def change(tails: Report) -> None:
        """Change the guest's tail of the main connection."""
        tails["all-ones"]["guest"]["main"] = tails["all-ones"]["host"]["owned"]

    staged.edit("unread-tails.json", change)


def more_pairs(_staged: Staged) -> None:
    """Pair one more connection than the corpus has."""
    EXTRA["paired"] = 1


def other_generator(staged: Staged) -> None:
    """Name another generator source in the manifest."""
    staged.manifest["generator_sha256"] = WRONG_SHA


def kept_account(staged: Staged) -> None:
    """Make the cleanup deletion fail."""

    def change(report: Report) -> None:
        """Give the reply to the deletion an error."""
        for frame in report["frames"]:
            if frame["is_reply"] and frame["id"] == 10:
                frame["error"] = WRONG_ERROR

    staged.edit("cleanup/report.json", change)


def other_rows(staged: Staged) -> None:
    """Change the published per-bit rows."""
    staged.edit("per-bit.json", lambda rows: rows.pop())


CHAIN: list[tuple[str, str, Break]] = [
    ("inventory", "Bitmap evidence inventory differs", fewer_reports),
    ("runtime", "Bitmap runtime identity differs", other_runtime),
    ("capture", "Bitmap host capture count/drop differs", dropped_packets),
    ("tails", "Bitmap unread tail inventory differs", extra_tails),
    ("provenance", "Bitmap plan/oracle provenance differs", other_driver),
    ("host and guest", "Bitmap unread host/guest tail differs", other_tail),
    ("pairs", "Bitmap paired TCP lifetime count differs", more_pairs),
    ("generator", "Bitmap plan generator source differs", other_generator),
    ("semantic", "Owned account cleanup/baseline differs", kept_account),
    ("rows", "Published per-bit evidence differs", other_rows),
]


@pytest.fixture(autouse=True)
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the packet readers and the capture replay of the verifier."""
    EXTRA["paired"] = 0
    monkeypatch.setattr(module, "read_packets", stub_packets)
    monkeypatch.setattr(module, "reconcile", stub_reconcile)
    monkeypatch.setattr(module, "verify_capture", stub_capture)


class CorpusOrderTests:
    """Keep the corpus checks in the order in which they have run."""

    def test_the_retained_corpus_passes_with_the_stubs(self, tmp_path: Path) -> None:
        """A mirror of the corpus passes every check that is not stubbed."""
        Staged.build(tmp_path).verify()

    @pytest.mark.parametrize("first", range(len(CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        staged = Staged.build(tmp_path)
        for _label, _message, apply in reversed(CHAIN[first:]):
            apply(staged)
        _label, message, _apply = CHAIN[first]
        with pytest.raises(ValueError, match=message):
            staged.verify()
