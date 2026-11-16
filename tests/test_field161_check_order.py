"""Pin the order of the field-161 verifier's checks.

``verify`` stops at the capture gate (decision D18) before it reaches the
readiness, selection and case checks, so the corpus replay and the corpus-fault
table never exercise them. These tests call ``check_readiness``,
``check_selection`` and ``check_case`` directly on a mirror of the retained
corpus. ``data/field161_check_order.tsv`` lists faults put into its JSON files
(and, with the change ``empty``, its text receipts), singly and in pairs, with the
ending that each produced on the scripts as they stood at commit ``f104c76``,
before the verifier was split into ``verify_classic_field161_matrix_*`` modules.
A pair shows the order of two checks: the ending is the one of the check that
runs first. A line with no faults records the ending of the unchanged corpus.
"""

import contextlib
import json
import tempfile
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import Mirror
from mutation_support import ending, fault_state, read_table
from pcap_tcp import read_packets
from verify_classic_field161_matrix import (
    VARIANTS,
    check_case,
    check_readiness,
    check_selection,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/classic-field161-01"
)
TABLE = Path(__file__).with_name("data") / "field161_check_order.tsv"
MANIFEST = "manifest.json"
JSON_FILES = [MANIFEST, "terminal.json", "pcap-inventory.json"]
TEXT_FILES = [
    "host-recorder-journal.txt",
    "ns-recorder-journal.txt",
    "units-terminal.txt",
    "former-pids-terminal.txt",
]

type State = dict[str, typ.Any]


def state_of_corpus() -> State:
    """Read the files that the faults may change, JSON parsed and text as it is.

    Returns
    -------
    dict[str, typing.Any]
        The file contents, keyed by path relative to the corpus.
    """
    names = list(JSON_FILES)
    for label in ("host", "ns"):
        names += [f"{label}-ready-launch.json", f"{label}-ready-before-a7.json"]
        names += [f"{case}/{label}-ready-before-connect.json" for case in VARIANTS]
    names += [f"{case}/proxy/report.json" for case in VARIANTS]
    state: State = {n: json.loads((CORPUS / n).read_text()) for n in names}
    state.update({n: (CORPUS / n).read_text() for n in TEXT_FILES})
    return state


ORIGINAL = state_of_corpus()
PACKETS = {
    "pcaps/" + p.name: read_packets(p) for p in (CORPUS / "pcaps").glob("*.pcap")
}


@contextlib.contextmanager
def mirrored(state: State) -> cabc.Iterator[Path]:
    """Mirror the corpus with every changed file written back.

    Yields
    ------
    pathlib.Path
        The root of the mirror, which is removed afterwards.
    """
    with tempfile.TemporaryDirectory() as scratch:
        root = Path(scratch) / CORPUS.name
        root.mkdir()
        mirror = Mirror(CORPUS, root)
        for name, value in state.items():
            if value != ORIGINAL[name]:
                text = value if isinstance(value, str) else json.dumps(value)
                mirror.thaw(name).write_text(text)
        yield root


def call_for(subject: str) -> cabc.Callable[[State], object]:
    """Build the check that a subject names, to run on a faulted state.

    Returns
    -------
    collections.abc.Callable
        A function from a state to the result of the check.
    """

    def call(state: State) -> object:
        """Run the check on a mirror that holds the changed files.

        Returns
        -------
        object
            What the check returned.
        """
        with mirrored(state) as root:
            manifest = state[MANIFEST]
            if subject == "readiness":
                return check_readiness(root, manifest)
            if subject == "selection":
                return check_selection(root, manifest, PACKETS)
            return check_case(root, subject, manifest["cases"][subject], PACKETS)

    return call


ROWS = read_table(TABLE)
CALLS = {subject: call_for(subject) for subject in {row[0] for row in ROWS}}


class Field161CheckOrderTests:
    """Keep the readiness, selection and case checks in the order they ran in."""

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        state = fault_state(ORIGINAL, faults)
        assert ending(CALLS[subject], state) == expected, "ending differs"
