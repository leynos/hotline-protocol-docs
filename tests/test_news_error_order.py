"""Pin the order of the news verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
record is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/news_error_order.tsv`` lists faults put into retained
records, singly and in pairs, with the ending that each produced on the version
of the scripts before the verifier was split into ``verify_native_news_*``
modules (commit 0b34126). A pair of faults shows the order of the two checks:
the ending is the one of the check that runs first.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from mutation_support import ending, fault_state, read_table
from native_news_cases import bodies, structures
from verify_native_auth import reply
from verify_native_news import article_records, body_reply, category_view, structure
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    import collections.abc as cabc

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-news-01"
)
TABLE = Path(__file__).with_name("data") / "news_error_order.tsv"
THREADED = [1, 4, 6, 5, 2, 3]
ROOT_ENTRIES = [
    (b"bundle", True, 2),
    (b"category", False, 6),
    (b"empty", True, 0),
    (b"hi-\x9a", True, 0),
    (b"zero-articles", False, 0),
]
LISTED_VERSION = 15
LIST_ID = 10
ARTICLES = 321
STRUCTURES = [
    "delete-low-category",
    "category-conflict-folder",
    "folder-missing-parent",
]
BODIES = ["root-first", "unknown-flavour"]

type Subject = tuple[typ.Any, cabc.Callable[[typ.Any], object]]


def report(name: str) -> dict[str, typ.Any]:
    """Load one retained report.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``report.json``.
    """
    return json.loads((BATCH / name / "report.json").read_text())


def subjects() -> dict[str, Subject]:
    """Build each subject: the evidence to fault and the check to run on it.

    Returns
    -------
    dict[str, tuple[typing.Any, collections.abc.Callable]]
        The evidence and the check of each subject, by name.
    """
    found: dict[str, Subject] = {}
    for label in STRUCTURES:
        expected = structures()[label][1]
        found[f"structure-{label}"] = (
            {"report": report(f"structures/{label}"), "expected": expected},
            lambda s: structure(s["report"], s["expected"]),
        )
    grandchild = report("grandchild")
    listed = fields(reply(grandchild, 40))[ARTICLES]
    by_id = {r["id"]: r for r in article_records(listed, THREADED)}
    for label in BODIES:
        expected = bodies()[label][1]
        found[f"body-{label}"] = (
            {"report": report(f"bodies/{label}"), "expected": expected},
            lambda s: body_reply(s["report"], s["expected"], by_id),
        )
    found["article-list"] = (
        {"hex": listed.hex()},
        lambda s: article_records(bytes.fromhex(s["hex"]), THREADED),
    )
    found[f"categories-{LISTED_VERSION}"] = (
        {"report": report(f"listings/version-{LISTED_VERSION}")},
        lambda s: category_view(
            reply(s["report"], LIST_ID), LISTED_VERSION, ROOT_ENTRIES
        ),
    )
    return found


SUBJECTS = subjects()
ROWS = read_table(TABLE)


class NewsOrderTests:
    """Keep the news checks in the order in which they have run."""

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
