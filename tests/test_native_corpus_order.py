"""Pin the order of the native verifiers' corpus checks.

The goldens observe only the retained corpora, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Each ``data/<family>_corpus_order.tsv`` lists faults put into the JSON
files of one retained corpus, singly and in pairs, with the ending that each
produced on the scripts as they stood at commit 8a3f8cd, before the verifier was
split into helper modules. The verifier hashes every file against the manifest and
``SHA256SUMS``, so the digest of a faulted file is refreshed in both before the
verifier runs; the packet readers are the verifier's own. A pair of faults shows
the order of the two checks: the ending is the one of the check that runs first.
"""

import functools
import typing as typ
from pathlib import Path

import pytest
from corpus_order_subjects import corpus_subject
from mutation_support import ending, fault_state, read_table

DATA = Path(__file__).with_name("data")
ROWS = [
    (path.stem, *row)
    for path in sorted(DATA.glob("*_corpus_order.tsv"))
    for row in read_table(path)
]


@functools.cache
def subject(name: str) -> tuple[typ.Any, typ.Any]:
    """Build the subject of one corpus verifier once.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The corpus's JSON files and the check that runs the verifier on a copy.
    """
    return corpus_subject(name)


class NativeCorpusOrderTests:
    """Keep the corpus checks of each verifier in the order in which they have run."""

    @pytest.mark.parametrize(
        ("table", "name", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}-{row[1]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, table: str, name: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        assert table.endswith("_corpus_order"), "a table of corpus faults"
        state, call = subject(name)
        assert ending(call, fault_state(state, faults)) == expected, "ending differs"
