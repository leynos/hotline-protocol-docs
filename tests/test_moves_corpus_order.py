"""Pin the order of the move verifier's corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. The packet records are not read: the tests replace the readers and
the capture replay of every ``verify_native_moves`` module with stubs, so each
expectation is about the order in which ``verify`` makes its own checks. Every
expectation was observed on the version of the scripts before the verifier was
split into ``verify_native_moves_*`` modules (commit 0b34126).

A corpus that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import Mirror, patch_everywhere
from verify_native_moves import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-move-01"
)
MODULES = "verify_native_moves"
PACKETS = 1875
STATE = {"short": False}
WRONG_ERROR = 1
SAME_PARENT = "moves/file-same-parent"
ACK_ID = 13
LISTING_ID = 10
LOW_ID = 20
CLEANUP_LISTING_ID = 90
ACCESS_FIELD = 110
WRONG_SHA = "0" * 64


def stub_packets(_path: Path) -> list[None]:
    """Stand in for the packet reader.

    Returns
    -------
    list[None]
        As many records as the capture holds, or one fewer.
    """
    return [None] * (PACKETS - STATE["short"])


def stub_reconcile(*_args: object) -> list[None]:
    """Stand in for the packet reconciliation.

    Returns
    -------
    list[None]
        An empty list.
    """
    return []


def stub_capture(path: Path) -> Report:
    """Stand in for the capture replay.

    Returns
    -------
    dict[str, typing.Any]
        The report that the replay would have returned.
    """
    return json.loads((path / "report.json").read_text())


type Break = cabc.Callable[[Mirror], None]


def reply_of(report: Report, identifier: int) -> Report:
    """Find the reply with ``identifier`` in a report.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    return next(f for f in report["frames"] if f["is_reply"] and f["id"] == identifier)


def other_process(mirror: Mirror) -> None:
    """Name another emulator process in the runtime record."""
    mirror.edit_json("runtime-check.json", lambda r: r.update(emulator_pid=1))


def fewer_reports(mirror: Mirror) -> None:
    """Leave one report out of the manifest."""
    mirror.edit_json("manifest.json", lambda m: m["reports"].pop())


def short_capture(_mirror: Mirror) -> None:
    """Make the packet reader return one record too few."""
    STATE["short"] = True


def other_steps(mirror: Mirror) -> None:
    """Record other steps in the first plan."""
    mirror.edit_json("preflight/plan.json", lambda p: p.update(steps=[]))


def other_profile(mirror: Mirror) -> None:
    """Record another profile in the first report."""
    mirror.edit_json("preflight/report.json", lambda r: r.update(profile="other"))


def failed_noop(mirror: Mirror) -> None:
    """Give the same-parent move an error."""
    mirror.edit_json(
        f"{SAME_PARENT}/report.json",
        lambda r: reply_of(r, ACK_ID).update(error=WRONG_ERROR),
    )


def shorter_listing(mirror: Mirror) -> None:
    """Leave one name out of the preflight listing."""
    mirror.edit_json(
        "preflight/report.json", lambda r: reply_of(r, LISTING_ID)["fields"].pop()
    )


def other_bitmap(mirror: Mirror) -> None:
    """Change the access bitmap that the low account read in the preflight."""

    def change(report: Report) -> None:
        """Change the bitmap field of the low account's reply."""
        for field in reply_of(report, LOW_ID)["fields"]:
            if field["id"] == ACCESS_FIELD:
                field["hex"] = "ff"

    mirror.edit_json("preflight/report.json", change)


def failed_seed(mirror: Mirror) -> None:
    """Give a frame of the seed an error."""
    mirror.edit_json(
        "seed/report.json", lambda r: r["frames"][0].update(error=WRONG_ERROR)
    )


def shorter_cleanup(mirror: Mirror) -> None:
    """Leave one name out of the cleanup listing."""
    mirror.edit_json(
        "cleanup/report.json",
        lambda r: reply_of(r, CLEANUP_LISTING_ID)["fields"].pop(),
    )


def more_reports(mirror: Mirror) -> None:
    """Record one more completed report than the corpus has."""
    mirror.edit_json("manifest.json", lambda m: m.update(completed_reports=99))


def lost_query(mirror: Mirror) -> None:
    """Remove the first oracle query."""
    first = min(p for p in (mirror.root / "oracle-queries").glob("*.json"))
    first.unlink()


def other_query(mirror: Mirror) -> None:
    """Name another program in the last oracle query."""
    last = max((mirror.root / "oracle-queries").glob("*.json"))
    mirror.edit_json(
        f"oracle-queries/{last.name}", lambda q: q["program"].update(sha256=WRONG_SHA)
    )


CHAIN: list[tuple[str, str, Break]] = [
    ("runtime", "Move runtime identity differs", other_process),
    ("reports", "Move report inventory differs", fewer_reports),
    ("packets", "Move packet inventory differs", short_capture),
    ("plan", "Move as-run plan differs", other_steps),
    ("provenance", "Move capture provenance/completion differs", other_profile),
    ("move", "ACK/error", failed_noop),
    ("preflight", "Move preflight names were not absent", shorter_listing),
    ("low account", "Low-account preflight bitmap differs", other_bitmap),
    ("auxiliary", "Move auxiliary operation failed", failed_seed),
    ("cleanup", "did not restore Files wire listing", shorter_cleanup),
    ("aggregates", "Move aggregate counts differ", more_reports),
    ("queries", "Move oracle inventory differs", lost_query),
    ("identity", "Move oracle identity/code differs", other_query),
]


@pytest.fixture(autouse=True)
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the packet readers and the capture replay of the verifier."""
    STATE["short"] = False
    patch_everywhere(monkeypatch, MODULES, "read_packets", stub_packets)
    patch_everywhere(monkeypatch, MODULES, "reconcile", stub_reconcile)
    patch_everywhere(monkeypatch, MODULES, "verify_capture", stub_capture)


class CorpusOrderTests:
    """Keep the corpus checks in the order in which they have run."""

    def test_the_retained_corpus_passes_with_the_stubs(self, tmp_path: Path) -> None:
        """A mirror of the corpus passes every check that is not stubbed."""
        verify(Mirror(BATCH, tmp_path).root)

    @pytest.mark.parametrize("first", range(len(CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        mirror = Mirror(BATCH, tmp_path)
        for _label, _message, apply in reversed(CHAIN[first:]):
            apply(mirror)
        _label, message, _apply = CHAIN[first]
        with pytest.raises(ValueError, match=message):
            verify(tmp_path)
