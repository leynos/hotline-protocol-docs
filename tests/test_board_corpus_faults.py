"""Pin the order of the board verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. ``data/board_corpus_faults.tsv`` lists faults put into the JSON files
of the retained corpus, singly and in pairs, with the ending that each produced on
the version of the scripts before the verifier was split into
``verify_native_board_*`` modules (commit 0b34126). The verifier hashes every
file against the manifest, so the digest of a faulted file is refreshed in the
manifest and in ``SHA256SUMS`` before the verifier runs; the packet readers are
the verifier's own. A pair of faults shows the order of the two checks: the
ending is the one of the check that runs first.
"""

import copy
import hashlib
import json
import tempfile
import typing as typ
from pathlib import Path

import pytest
from corpus_mirror import Mirror
from mutation_support import ending, fault_state, read_table
from verify_native_board import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/native-board-01"
)
TABLE = Path(__file__).with_name("data") / "board_corpus_faults.tsv"
MANIFEST = "manifest.json"
SUMS = "SHA256SUMS"
CORPUS_KEY = "corpus"  # the verifier reports the directory it was given

type State = dict[str, typ.Any]


def board_subject() -> tuple[State, cabc.Callable[[State], object]]:
    """Describe the corpus as its JSON files, and a check that runs on a faulted copy.

    Returns
    -------
    tuple[dict[str, typing.Any], collections.abc.Callable]
        The parsed files, and a function that mirrors the corpus with the changed
        files and their refreshed digests written back, and runs ``verify`` on it.
    """
    original = {
        str(path.relative_to(CORPUS)): json.loads(path.read_text())
        for path in sorted(CORPUS.rglob("*.json"))
    }

    def call(state: State) -> object:
        """Run ``verify`` on a mirror that holds the changed files.

        Returns
        -------
        object
            What ``verify`` returned, without the directory it was given.
        """
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / CORPUS.name
            root.mkdir()
            mirror = Mirror(CORPUS, root)
            manifest = copy.deepcopy(state[MANIFEST])
            for name, value in state.items():
                if name != MANIFEST and value != original[name]:
                    raw = json.dumps(value).encode()
                    mirror.edit_bytes(name, lambda _old, new=raw: new)
                    if name in manifest.get("files", {}):
                        manifest["files"][name] = hashlib.sha256(raw).hexdigest()
            mirror.write_json(MANIFEST, manifest)
            files = sorted(manifest.get("files", {}).items())
            mirror.edit_bytes(
                SUMS,
                lambda _old: "".join(f"{d}  {n}\n" for n, d in files).encode(),
            )
            return {k: v for k, v in verify(root).items() if k != CORPUS_KEY}

    return original, call


STATE, CALL = board_subject()
ROWS = read_table(TABLE)


class BoardCorpusFaultTests:
    """Keep the board checks in the order in which they have run."""

    @pytest.mark.parametrize(
        ("subject", "faults", "expected"),
        ROWS,
        ids=[f"{i}-{row[0]}" for i, row in enumerate(ROWS)],
    )
    def test_the_recorded_faults_end_as_they_did(
        self, subject: str, faults: list[tuple[str, str]], expected: str
    ) -> None:
        """Each recorded fault, alone or paired, ends with the recorded message."""
        assert subject == "board-corpus", "only the board corpus is recorded"
        assert ending(CALL, fault_state(STATE, faults)) == expected, "ending differs"
