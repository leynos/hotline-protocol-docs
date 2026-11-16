"""Pin the order of the missing-alias planner's checks.

The goldens observe only the plans that the planner emits for sound records, so the
order in which it refuses an unsound record is held here, outside ``scripts/tests``,
whose tests are the golden keys. ``data/missing_alias_error_order.tsv`` lists
faults put into a runtime record and the port, singly and in pairs, with the ending
that each produced on the scripts as they stood at commit 8a3f8cd, before the
planner was restructured. A pair of faults shows the order of the two checks: the
ending is the one of the check that runs first.
"""

from pathlib import Path

import pytest
from missing_alias_subjects import subjects
from mutation_support import ending, fault_state, read_table

TABLE = Path(__file__).with_name("data") / "missing_alias_error_order.tsv"
SUBJECTS = subjects()
ROWS = read_table(TABLE)


class MissingAliasOrderTests:
    """Keep the planner's checks in the order in which they have run."""

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
