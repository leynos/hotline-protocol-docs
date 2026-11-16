"""Pin the order of the native planners' refusals.

The goldens observe only the plans that a planner emits for a sound runtime record,
so the order in which it refuses an unsound one is held here, outside
``scripts/tests``, whose tests are the golden keys. ``data/planner_order.tsv`` lists
faults put into a retained runtime record and into the port, singly and in pairs,
with the ending that each produced on the scripts as they stood at commit 8a3f8cd,
before the planners were restructured. A pair of faults shows the order of the two
checks: the ending is the one of the check that runs first.
"""

import functools
import typing as typ
from pathlib import Path

import pytest
from mutation_support import ending, fault_state, read_table
from planner_order_subjects import planner_subject

TABLE = Path(__file__).with_name("data") / "planner_order.tsv"
ROWS = read_table(TABLE)


@functools.cache
def subject(name: str) -> tuple[typ.Any, typ.Any]:
    """Build the subject of one planner once.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The runtime record and port, and the planner's checks on them.
    """
    return planner_subject(name)


class PlannerOrderTests:
    """Keep each planner's checks in the order in which they have run."""

    @pytest.mark.parametrize(
        ("name", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, name: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        state, call = subject(name)
        assert ending(call, fault_state(state, faults)) == expected, "ending differs"
