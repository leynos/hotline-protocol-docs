"""Pin the order of the article-deletion verifier's corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. The packet records are not read: the tests replace the readers and
the capture replay of every ``verify_native_article_deletion`` module with stubs,
so each expectation is about the order in which ``verify`` makes its own checks.
Every expectation was observed on the version of the scripts before the verifier
was split into ``verify_native_article_deletion_*`` modules (commit 0b34126).

A corpus that breaks check ``n`` also breaks every check after it, so the
message that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import Mirror, patch_everywhere
from verify_native_article_deletion import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-article-delete-01"
)
MODULES = "verify_native_article_deletion"
FIRST = "initial/preflight"
SECOND = "initial/burst"
INITIAL_PACKETS = 321
RECOVERY_PACKETS = 2198
STATE = {"short": False}
WRONG_SHA = "0" * 64
LATE = "2999-01-01T00:00:00+00:00"
SLOW_NS = 10**12


def stub_packets(path: Path) -> list[None]:
    """Stand in for the packet reader.

    Returns
    -------
    list[None]
        As many records as the capture of the phase holds, or one fewer.
    """
    count = RECOVERY_PACKETS if "recovery" in path.name else INITIAL_PACKETS
    return [None] * (count - STATE["short"])


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


def fewer_inventory(mirror: Mirror) -> None:
    """Leave one case out of the resume inventory."""
    mirror.edit_json("resume-inventory.json", lambda i: i.pop(next(iter(i))))


def fewer_reports(mirror: Mirror) -> None:
    """Leave one report out of the manifest."""
    mirror.edit_json("manifest.json", lambda m: m["reports"].pop(FIRST))


def short_capture(_mirror: Mirror) -> None:
    """Make the packet reader return one record too few."""
    STATE["short"] = True


def other_process(mirror: Mirror) -> None:
    """Name another emulator process in the runtime record."""
    mirror.edit_json("runtime.json", lambda r: r.update(emulator_pid=1))


def other_application(mirror: Mirror) -> None:
    """Name another application catalogue entry."""
    mirror.edit_json(
        "recovery-application-identity.json", lambda a: a.update(catalog=1)
    )


def other_environment(mirror: Mirror) -> None:
    """Record another environment in the first plan."""
    mirror.edit_json(f"{FIRST}/plan.json", lambda p: p.update(environment={}))


def other_steps(mirror: Mirror) -> None:
    """Record other steps in the first plan."""
    mirror.edit_json(f"{FIRST}/plan.json", lambda p: p.update(steps=[]))


def other_profile(mirror: Mirror) -> None:
    """Record another profile in the first report."""
    mirror.edit_json(f"{FIRST}/report.json", lambda r: r.update(profile="other"))


def other_requests(mirror: Mirror) -> None:
    """Record other sent bytes in the first report."""

    def change(report: Report) -> None:
        """Change the sent bytes of every stream."""
        for stream in report["streams"].values():
            stream["sent_hex"] += "00"

    mirror.edit_json(f"{FIRST}/report.json", change)


def late_start(mirror: Mirror) -> None:
    """Record that the first case ended after the second began."""
    mirror.edit_json(f"{FIRST}/report.json", lambda r: r.update(recorded_at_utc=LATE))


def slow_burst(mirror: Mirror) -> None:
    """Record that the burst ended after more than a minute."""
    mirror.edit_json(
        f"{SECOND}/report.json", lambda r: r["events"][-1].update(elapsed_ns=SLOW_NS)
    )


CHAIN: list[tuple[str, str, Break]] = [
    ("inventory", "Deletion case inventory differs", fewer_inventory),
    ("reports", "Deletion report inventory differs", fewer_reports),
    ("packets", "Deletion host packet count differs", short_capture),
    ("runtimes", "Deletion runtime identities differ", other_process),
    ("application", "Recovery native application identity differs", other_application),
    ("environment", "As-run runtime provenance differs", other_environment),
    ("plan", "Deletion as-run plan differs", other_steps),
    ("provenance", "Deletion capture provenance differs", other_profile),
    ("requests", "Recorded requests differ from executed plan prefix", other_requests),
    ("chronology", "Deletion phase chronology differs", late_start),
    ("burst", "Retained flood burst differs", slow_burst),
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
