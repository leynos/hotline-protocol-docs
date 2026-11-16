"""Pin the order of the room verifier's corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. The packet records are not read: the tests replace the readers, the
packet reconciliation and the capture replay of every ``verify_native_rooms``
module with stubs, so each expectation is about the order in which ``verify``
makes its own checks. Every expectation was observed on the version of the
scripts before the verifier was split into ``verify_native_rooms_*`` modules
(commit 0b34126).

A corpus that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import Mirror, patch_everywhere
from verify_native_rooms import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-rooms-01"
)
MODULES = "verify_native_rooms"
PACKETS = 2095
PREFLIGHT = "preflight"
RECOVERY = "recovery-inspect"
STATE: dict[str, typ.Any] = {"short": False, "names": iter(())}
OBSERVATIONS = json.loads((CORPUS / "packet-observations.json").read_text())
ORDER = list(json.loads((CORPUS / "manifest.json").read_text())["reports"])
FIRST = ORDER[0]
WRONG_ERROR = 1
WRONG_SHA = "0" * 64
LATE = "2999-01-01T00:00:00+00:00"
RECORDER_SOURCE = "sources/protocol_capture.py.final.txt"
BASELINE_ID = 10
LISTING_ID = 11
NAME_PREFLIGHT_ID = 20
CLEANUP_ACCOUNTS_ID = 20


def stub_packets(_path: Path) -> list[None]:
    """Stand in for the packet reader.

    Returns
    -------
    list[None]
        As many records as the capture holds, or one fewer.
    """
    return [None] * (PACKETS - STATE["short"])


def stub_reconcile(*_args: object, **_kwargs: object) -> object:
    """Stand in for the packet reconciliation.

    Returns
    -------
    object
        The observations that the retained corpus records for the next report.
    """
    return OBSERVATIONS[next(STATE["names"])]


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


def fewer_reports(mirror: Mirror) -> None:
    """Leave one report out of the manifest."""
    mirror.edit_json("manifest.json", lambda m: m["reports"].pop())


def short_capture(_mirror: Mirror) -> None:
    """Make the packet reader return one record too few."""
    STATE["short"] = True


def other_environment(mirror: Mirror) -> None:
    """Record another environment in the first plan."""
    mirror.edit_json(f"{FIRST}/plan.json", lambda p: p.update(environment={}))


def other_profile(mirror: Mirror) -> None:
    """Record another profile in the first report."""
    mirror.edit_json(f"{FIRST}/report.json", lambda r: r.update(profile="other"))


def other_recorder(mirror: Mirror) -> None:
    """Record another recorder source in the manifest."""
    mirror.edit_json(
        "manifest.json", lambda m: m["as_run_sources"].update({RECORDER_SOURCE: "0"})
    )


def unfinished(mirror: Mirror) -> None:
    """Record the first report as failed."""
    mirror.edit_json(f"{FIRST}/report.json", lambda r: r.update(status="failed"))


def other_requests(mirror: Mirror) -> None:
    """Record other sent bytes in the first report."""

    def change(report: Report) -> None:
        """Change the sent bytes of every stream."""
        for stream in report["streams"].values():
            stream["sent_hex"] += "00"

    mirror.edit_json(f"{FIRST}/report.json", change)


def late_start(mirror: Mirror) -> None:
    """Record that the first report ended after the second began."""
    mirror.edit_json(
        f"{PREFLIGHT}/report.json", lambda r: r.update(recorded_at_utc=LATE)
    )


def other_observations(mirror: Mirror) -> None:
    """Change the packet observations that the corpus records."""
    mirror.edit_json("packet-observations.json", lambda o: o.pop(PREFLIGHT))


def shorter_baseline(mirror: Mirror) -> None:
    """Leave one account out of the preflight enumeration."""
    mirror.edit_json(
        f"{PREFLIGHT}/report.json", lambda r: reply_of(r, BASELINE_ID)["fields"].pop()
    )


def present_name(mirror: Mirror) -> None:
    """Make the preflight read of an owned name succeed."""
    mirror.edit_json(
        f"{PREFLIGHT}/report.json",
        lambda r: reply_of(r, NAME_PREFLIGHT_ID).update(error=0),
    )


def shorter_recovery(mirror: Mirror) -> None:
    """Leave one account out of the recovery enumeration."""
    mirror.edit_json(
        f"{RECOVERY}/report.json", lambda r: reply_of(r, BASELINE_ID)["fields"].pop()
    )


def shorter_cleanup(mirror: Mirror) -> None:
    """Leave one account out of the cleanup enumeration."""
    mirror.edit_json(
        "cleanup/report.json",
        lambda r: reply_of(r, CLEANUP_ACCOUNTS_ID)["fields"].pop(),
    )


def changed_source(mirror: Mirror) -> None:
    """Append a byte to the first as-run source."""
    sources = json.loads((CORPUS / "manifest.json").read_text())["as_run_sources"]
    first = next(name for name in sources if name != RECORDER_SOURCE)
    mirror.edit_bytes(first, lambda raw: raw + b"x")


def lost_query(mirror: Mirror) -> None:
    """Remove the first oracle query."""
    min((mirror.root / "oracle-queries").glob("*.json")).unlink()


def failed_query(mirror: Mirror) -> None:
    """Record that the last oracle query failed."""
    last = max((mirror.root / "oracle-queries").glob("*.json"))
    mirror.edit_json(
        f"oracle-queries/{last.name}", lambda q: q["result"].update(isError=True)
    )


CHAIN: list[tuple[str, str, Break]] = [
    ("reports", "Room report inventory differs", fewer_reports),
    ("packets", "Room recorder count/drops differ", short_capture),
    ("environment", "Room plan runtime differs", other_environment),
    ("profile", "Room oracle/profile differs", other_profile),
    ("recorder", "Room recorder source differs", other_recorder),
    ("plan", "Room completed plan differs", unfinished),
    ("requests", "Room request bytes differ", other_requests),
    ("chronology", "Room stage chronology differs", late_start),
    ("observations", "Room packet observations differ", other_observations),
    ("baseline", "Room original baseline differs", shorter_baseline),
    ("names", "Room owned name preflight/cleanup differs", present_name),
    ("recovery", "Same-session recovery inventory differs", shorter_recovery),
    ("restoration", "Room final baseline restoration differs", shorter_cleanup),
    ("sources", "Room as-run source changed", changed_source),
    ("count", "Room oracle query count differs", lost_query),
    ("query", "Room oracle query failed", failed_query),
]


@pytest.fixture(autouse=True)
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the packet readers and the capture replay of the verifier."""
    STATE["short"] = False
    STATE["names"] = iter(ORDER)
    patch_everywhere(monkeypatch, MODULES, "read_packets", stub_packets)
    patch_everywhere(monkeypatch, MODULES, "reconcile", stub_reconcile)
    patch_everywhere(monkeypatch, MODULES, "verify_capture", stub_capture)


class CorpusOrderTests:
    """Keep the corpus checks in the order in which they have run."""

    def test_the_retained_corpus_passes_with_the_stubs(self, tmp_path: Path) -> None:
        """A mirror of the corpus passes every check that is not stubbed."""
        verify(Mirror(CORPUS, tmp_path).root)

    @pytest.mark.parametrize("first", range(len(CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(
        self, first: int, tmp_path: Path
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        mirror = Mirror(CORPUS, tmp_path)
        for _label, _message, apply in reversed(CHAIN[first:]):
            apply(mirror)
        _label, message, _apply = CHAIN[first]
        with pytest.raises(ValueError, match=message):
            verify(tmp_path)
