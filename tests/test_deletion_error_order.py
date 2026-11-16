"""Pin the order of the article-deletion verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
record is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/deletion_error_order.tsv`` lists faults put into retained
records, singly and in pairs, with the ending that each produced on the version
of the scripts before the verifier was split into ``verify_native_article_deletion_*``
modules (commit 0b34126). A pair of faults shows the order of the two checks:
the ending is the one of the check that runs first.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from mutation_support import ending, fault_state, read_table
from native_news_delete_cases import specs
from verify_native_article_deletion import (
    deletion,
    graph,
    measured_wait,
    scalar_controls,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-article-delete-01"
)
TABLE = Path(__file__).with_name("data") / "deletion_error_order.tsv"
GRAPH_MODES = [
    "promote-parent",
    "recursive-parent",
    "leaf",
    "head",
    "tail",
    "unchanged",
    "promote-middle",
    "recursive-middle",
]

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
    for spec in specs():
        name = f"deletion-{spec['case']}"
        if (BATCH / "deletions" / spec["case"] / "report.json").exists():
            found[name] = (
                {"report": report(f"deletions/{spec['case']}"), "spec": spec},
                lambda s: deletion(s["report"], s["spec"]),
            )
    found["wait-pause"] = (
        {"report": report("resumed/leaf-one")},
        lambda s: measured_wait(s["report"], "pause"),
    )
    found["scalar"] = ({"specs": specs()}, lambda s: scalar_controls(s["specs"]))
    found["graph"] = (
        {"modes": GRAPH_MODES},
        lambda s: [graph(mode) for mode in s["modes"]],
    )
    return found


SUBJECTS = subjects()
ROWS = read_table(TABLE)


class DeletionOrderTests:
    """Keep the deletion checks in the order in which they have run."""

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
