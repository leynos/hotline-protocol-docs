"""Pin the order of the persistence verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
record is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/native_settings_persistence_check_order.tsv`` lists faults put
into the JSON files of the retained A46 and A48 corpus, singly and in pairs, with
the ending that each produced on the scripts as they stood at commit 46c28b6,
before the verifier was split into ``verify_native_settings_persistence_*``
modules. The subjects are the source, legacy-phase, planned-phase, readiness,
packet, storage and lifecycle checks, and the whole verifier; the copy that each
runs on refreshes the capture checksums, and for the whole verifier the manifest
and ``SHA256SUMS`` too, so that a fault reaches the check that reads it. A pair of
faults shows the order of the two checks: the ending is the one of the check that
runs first.
"""

from pathlib import Path

import pytest
from mutation_support import ending, fault_state, read_table
from persistence_order_subjects import subjects

TABLE = Path(__file__).with_name("data") / "native_settings_persistence_check_order.tsv"
SUBJECTS = subjects()
ROWS = read_table(TABLE)


class NativeSettingsPersistenceOrderTests:
    """Keep the persistence checks in the order in which they have run."""

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
