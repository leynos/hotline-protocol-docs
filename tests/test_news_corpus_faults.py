"""Pin the order of the news verifiers' corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/news_corpus_faults.tsv`` lists faults put into the JSON files
of the two retained corpora, singly and in pairs, with the ending that each
produced on the version of the scripts before the verifiers were split
(commit 0b34126). The packet records are not read: the tests replace the readers
and the capture replay of every news verifier module with stubs, so each ending
is the one of the first check that ``verify`` makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import corpus_subject, patch_everywhere
from mutation_support import ending, fault_state, read_table
from verify_native_news import verify as verify_news
from verify_native_news_boundary import verify as verify_boundary

if typ.TYPE_CHECKING:
    import collections.abc as cabc

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence/gap-remediation/2026-11-13"
NEWS = EVIDENCE / "native-news-01"
BOUNDARY = EVIDENCE / "native-news-boundary-01"
TABLE = Path(__file__).with_name("data") / "news_corpus_faults.tsv"
MODULES = "verify_native_news"
NEWS_PACKETS = 1246
BOUNDARY_PACKETS = 927
CURRENT = {"packets": 0}

type Subject = tuple[dict[str, typ.Any], cabc.Callable[[dict[str, typ.Any]], object]]


def files(corpus: Path, extra: list[str]) -> list[str]:
    """List the JSON files that can be faulted: the named ones and each case's.

    Returns
    -------
    list[str]
        The names, relative to ``corpus``.
    """
    found = [name for name in extra if (corpus / name).exists()]
    for path in sorted(corpus.rglob("report.json")):
        relative = path.parent.relative_to(corpus)
        found.append(str(relative / "report.json"))
        if (path.parent / "plan.json").exists():
            found.append(str(relative / "plan.json"))
    return found


def stub_packets(path: Path) -> list[None]:
    """Stand in for the packet reader.

    Returns
    -------
    list[None]
        As many records as the capture of the corpus holds.
    """
    return [None] * CURRENT["packets"]


def stub_reconcile(*_args: object) -> list[None]:
    """Stand in for the packet reconciliation.

    Returns
    -------
    list[None]
        An empty list.
    """
    return []


def stub_capture(path: Path) -> dict[str, typ.Any]:
    """Stand in for the capture replay.

    Returns
    -------
    dict[str, typing.Any]
        The report that the replay would have returned.
    """
    return json.loads((path / "report.json").read_text())


def subject(
    corpus: Path,
    verify: cabc.Callable[[Path], object],
    extra: list[str],
    packets: int,
) -> Subject:
    """Describe a corpus: its faultable files and a check that runs on a faulted copy.

    Returns
    -------
    tuple[dict[str, typing.Any], collections.abc.Callable]
        The parsed files, and the check, which tells the stub reader how many
        packet records this corpus holds.
    """
    state, run = corpus_subject(corpus, verify, files(corpus, extra))

    def call(faulted: dict[str, typ.Any]) -> object:
        """Run ``verify`` on a faulted copy of the corpus.

        Returns
        -------
        object
            What ``verify`` returned.
        """
        CURRENT["packets"] = packets
        return run(faulted)

    return state, call


SUBJECTS: dict[str, Subject] = {
    "news-corpus": subject(
        NEWS, verify_news, ["manifest.json", "runtime-check.json"], NEWS_PACKETS
    ),
    "boundary-corpus": subject(
        BOUNDARY,
        verify_boundary,
        ["manifest.json", "runtime.json", "runtime-check.json"],
        BOUNDARY_PACKETS,
    ),
}
ROWS = read_table(TABLE)


@pytest.fixture(autouse=True)
def stubs(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the packet readers and the capture replay of the verifiers."""
    patch_everywhere(monkeypatch, MODULES, "read_packets", stub_packets)
    patch_everywhere(monkeypatch, MODULES, "reconcile", stub_reconcile)
    patch_everywhere(monkeypatch, MODULES, "verify_capture", stub_capture)


class NewsCorpusFaultTests:
    """Keep the corpus checks in the order in which they have run."""

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        state, call = SUBJECTS[subject]
        assert ending(call, fault_state(state, faults)) == expected, "ending differs"
