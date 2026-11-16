"""Pin the order of the room verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
record is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/rooms_error_order.tsv`` lists faults put into retained
records, singly and in pairs, with the ending that each produced on the version
of the scripts before the verifier was split into ``verify_native_rooms_*``
modules (commit 0b34126). A pair of faults shows the order of the two checks:
the ending is the one of the check that runs first.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from mutation_support import ending, fault_state, read_table
from verify_native_rooms import identities, semantic

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-rooms-01"
)
TABLE = Path(__file__).with_name("data") / "rooms_error_order.tsv"
SEMANTIC = ["basics", "lifecycle", "concurrent", "invites", "formatting"]

type Subject = tuple[typ.Any, cabc.Callable[[typ.Any], object]]


def report(name: str) -> dict[str, typ.Any]:
    """Load one retained report.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``report.json``.
    """
    return json.loads((CORPUS / name / "report.json").read_text())


def subjects() -> dict[str, Subject]:
    """Build each subject: the evidence to fault and the check to run on it.

    Returns
    -------
    dict[str, tuple[typing.Any, collections.abc.Callable]]
        The evidence and the check of each subject, by name.
    """
    found: dict[str, Subject] = {}
    for name in SEMANTIC:
        found[f"rooms-semantic-{name}"] = (
            {"report": report(name)},
            lambda s, n=name: semantic(n, s["report"]),
        )
    found["rooms-identities-basics"] = (
        {"report": report("basics")},
        lambda s: identities(s["report"]),
    )
    return found


SUBJECTS = subjects()
ROWS = read_table(TABLE)


class RoomOrderTests:
    """Keep the room checks in the order in which they have run."""

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
