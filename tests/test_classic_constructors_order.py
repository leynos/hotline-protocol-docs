"""Pin the order of the Classic account-constructor verifier's checks.

The goldens observe only the retained trace, so the order in which an unsound
trace is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/classic_constructors_faults.tsv`` lists faults put into the
five JSON reports of the retained trace, singly and in pairs, with the ending that
each produced on the version of the verifier before it was brought to the
standard (commit 8a3f8cd). A pair of faults shows the order of the two checks.
"""

from pathlib import Path

import pytest
from mutation_support import ending, fault_state, read_table
from verify_classic_account_constructors import load_evidence, verify

TABLE = Path(__file__).with_name("data") / "classic_constructors_faults.tsv"
SUBJECT = "classic-constructors"
STATE = load_evidence()
ROWS = read_table(TABLE)


class ClassicConstructorsOrderTests:
    """Keep the verifier's checks in the order in which they have run."""

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        assert subject == SUBJECT, "only the constructor trace is recorded"
        assert ending(verify, fault_state(STATE, faults)) == expected, "ending differs"
