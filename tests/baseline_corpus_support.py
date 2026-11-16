"""Build a small synthetic baseline corpus for the baseline verifier's tests.

The verifier reads ``evidence/hotline-server-1.9`` beneath a root, the ledger
beneath ``docs`` and the three helper scripts beneath ``scripts``. This module
writes the smallest consistent tree of that shape, so that a test can break one
thing at a time and observe which check refuses it. It reads the helper bytes
from the pinned record, never from the live files, so that the pinned and the
current verifier both find the hashes they expect.
"""

import copy
import hashlib
import json
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import types

import pinned_source
import pytest

HELPERS = (
    "capture-ghidra-evidence.py",
    "extract-synhxd-evidence.py",
    "verify-baseline-evidence.py",
)
ORACLE = "ab" * 32
CORPUS = Path("evidence/hotline-server-1.9")
LEDGER = Path("docs/baseline-validity-ledger.md")
CODE = "int main(void) { return 0; }\n"
LEDGER_TEXT = (
    "# Ledger\n\n"
    "| V001 | First claim. | Doc defect | Note one. |\n"
    "| M002 | Second claim. | Confirmed | Note two. |\n"
    "| V003 | Third claim. | Doc defect | Note three. |\n\n"
    "[binary]: ../evidence/hotline-server-1.9/inputs/a.txt\n"
    "See [handler](../evidence/hotline-server-1.9/queries/A-1.c).\n"
)


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def query_record(
    query: dict[str, typ.Any], data: dict[str, typ.Any]
) -> dict[str, typ.Any]:
    """Wrap a structured result the way a retained query record does.

    Returns
    -------
    dict[str, typing.Any]
        The record.
    """
    return {
        "query": copy.deepcopy(query),
        "program": {"sha256": ORACLE},
        "result": {"isError": False, "structuredContent": data},
    }


class Corpus:
    """A consistent synthetic corpus whose parts a test may alter before writing.

    Attributes
    ----------
    root : pathlib.Path
        The directory that plays the repository root.
    manifest : dict[str, typing.Any]
        The manifest, as it will be written.
    plans : dict[str, list[dict[str, typing.Any]]]
        Plan file name to its queries.
    records : dict[str, dict[str, typing.Any]]
        Query identifier to its saved record.
    code : dict[str, str]
        Query identifier to the text of its ``.c`` export.
    claims : dict[str, typing.Any]
        The claim index, as it will be written.
    ledger : str
        The ledger text.
    """

    def __init__(self, root: Path) -> None:
        """Lay out the default, consistent corpus in memory.

        Parameters
        ----------
        root : pathlib.Path
            The directory that plays the repository root.
        """
        self.root = root
        pins = pinned_source.Pins()
        self.helpers = {name: pins.read(name) for name in HELPERS}
        self.input_text = b"input snapshot\n"
        self.plans: dict[str, list[dict[str, typ.Any]]] = {
            "01-first.json": [
                {"id": "A-1", "tool": "decompile_function", "arguments": {}},
                {"id": "B-1", "tool": "list_data_items", "arguments": {"offset": 0}},
            ],
            "02-second.json": [
                {"id": "B-2", "tool": "list_data_items", "arguments": {"offset": 2}},
                {"id": "C-1", "tool": "get_function", "arguments": {}},
            ],
        }
        data: dict[str, dict[str, typ.Any]] = {
            "A-1": {"code": CODE, "truncated": False},
            "B-1": {"offset": 0, "items": ["x", "y"], "total": 3},
            "B-2": {"offset": 2, "items": ["z"], "total": 3},
            "C-1": {"name": "f", "has_more": False},
        }
        self.records = {
            query["id"]: query_record(query, data[query["id"]])
            for queries in self.plans.values()
            for query in queries
        }
        self.code = {"A-1": CODE}
        self.ledger = LEDGER_TEXT
        self.index_ledger = True  # False: the test sets the index hash itself
        self.manifest: dict[str, typ.Any] = {
            "program": {"sha256": ORACLE},
            "helper_scripts": [
                {"path": f"scripts/{name}", "sha256": sha(blob)}
                for name, blob in self.helpers.items()
            ],
            "inputs": [{"snapshot": "inputs/a.txt", "sha256": sha(self.input_text)}],
            "capture_count": 4,
            "ledger_claim_count": 3,
        }
        self.claims: dict[str, typ.Any] = {
            "ledger_sha256": "",
            "claims": [{"id": "V001"}, {"id": "M002"}, {"id": "V003"}],
        }

    def data(self, identifier: str) -> dict[str, typ.Any]:
        """Return the structured result of a saved query, for editing.

        Returns
        -------
        dict[str, typing.Any]
            The live dictionary.
        """
        return self.records[identifier]["result"]["structuredContent"]

    def write(self) -> Path:
        """Write every file of the corpus.

        Returns
        -------
        pathlib.Path
            The root.
        """
        evidence = self.root / CORPUS
        for name, blob in self.helpers.items():
            self.put(self.root / "scripts" / name, blob)
        self.put(evidence / "inputs/a.txt", self.input_text)
        self.put(evidence / "manifest.json", json.dumps(self.manifest).encode())
        for name, queries in self.plans.items():
            self.put(evidence / "plans" / name, json.dumps(queries).encode())
        for identifier, record in self.records.items():
            self.put(
                evidence / "queries" / f"{identifier}.json",
                json.dumps(record).encode(),
            )
        for identifier, text in self.code.items():
            self.put(evidence / "queries" / f"{identifier}.c", text.encode())
        self.put(self.root / LEDGER, self.ledger.encode())
        claims = copy.deepcopy(self.claims)
        if self.index_ledger:
            claims["ledger_sha256"] = sha(self.ledger.encode())
        self.put(evidence / "claims.json", json.dumps(claims).encode())
        return self.root

    @staticmethod
    def put(path: Path, data: bytes) -> None:
        """Write a file, creating its directory."""
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)


def refused(verifier: types.ModuleType, corpus: Corpus) -> Exception:
    """Write the corpus and run the verifier, returning what it raised.

    Parameters
    ----------
    verifier : types.ModuleType
        The script under test.
    corpus : Corpus
        The corpus to write and verify.

    Returns
    -------
    Exception
        The exception; the test fails if none is raised.
    """
    root = corpus.write()
    with pytest.raises((ValueError, LookupError, OSError)) as caught:
        verifier.verify(root)
    return caught.value


def expect(
    verifier: types.ModuleType,
    corpus: Corpus,
    message: str,
    *,
    starts: bool = False,
) -> None:
    """Require that the verifier refuses the corpus with a ``ValueError``.

    Parameters
    ----------
    verifier : types.ModuleType
        The script under test.
    corpus : Corpus
        The corpus to write and verify.
    message : str
        The exact message, or its start when ``starts`` is set.
    starts : bool
        Compare only the start of the message.
    """
    error = refused(verifier, corpus)
    text = str(error)
    matched = text.startswith(message) if starts else text == message
    if not (isinstance(error, ValueError) and matched):
        pytest.fail(f"expected ValueError {message!r}, got {error!r}")
