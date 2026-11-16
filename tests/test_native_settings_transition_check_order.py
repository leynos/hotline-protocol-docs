"""Pin the order of the checks of the same-session 304 transition driver.

The goldens observe only the retained corpus, so the order in which an unsound
record is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/native_settings_transition_check_order.tsv`` lists faults put
into the report and the plan of the retained capture, singly and in pairs, with the
ending that each produced on ``verify_native_settings_transition`` as it stood at
its pinned commit, before it was split. The subjects are ``semantic`` on the whole
report and ``semantic`` with ``completed_only`` off, which reads no restore and does
not require the capture to have completed. There is one fault for each leaf of the
frames, of the events that the gates read, of the plan's expectation and of its first
steps, the faults that the gates ignore being thinned to one in twelve; a pair of
faults is drawn, with a fixed seed, from faults that ended differently, so that the
ending of the pair is the one of the check that runs first.
"""

from pathlib import Path

import pytest
from capture_driver_subjects import subjects
from mutation_support import ending, fault_state, read_table

TABLE = Path(__file__).with_name("data") / "native_settings_transition_check_order.tsv"
SUBJECTS = subjects()
ROWS = read_table(TABLE)


class NativeSettingsTransitionOrderTests:
    """Keep the checks of the transition driver in the order in which they have run."""

    @pytest.mark.parametrize(
        ("name", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, name: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        state, call = SUBJECTS[name]
        assert ending(call, fault_state(state, faults)) == expected, "ending differs"
