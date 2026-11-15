"""Tests for the corpus identity rule (decision D22)."""

import json
import typing as typ

import evidence_corpus
import pytest
from tool_support import MissingInputError

if typ.TYPE_CHECKING:
    from pathlib import Path

CASES = [
    (
        "evidence/gap-remediation/2026-11-13/native-pm-01/a/b.json",
        "evidence/gap-remediation/2026-11-13/native-pm-01",
    ),
    (
        "evidence/protocol-gap-analysis/2026-11-15/revision-89/inputs/x.txt",
        "evidence/protocol-gap-analysis/2026-11-15/revision-89",
    ),
    (
        "evidence/protocol-gap-analysis/2026-11-12/manifest.json",
        "evidence/protocol-gap-analysis/2026-11-12/manifest.json",
    ),
    (
        "evidence/gap-remediation/2026-11-13/native-pm-01",
        "evidence/gap-remediation/2026-11-13/native-pm-01",
    ),
    (
        "evidence/hotline-server-1.9/queries/q1.json",
        "evidence/hotline-server-1.9/queries",
    ),
    (
        "evidence/hotline-server-1.9/claims.json",
        "evidence/hotline-server-1.9/(root)",
    ),
    ("evidence/gap-remediation/README.md", None),
    ("evidence/gap-remediation/2026-11-13", None),
    ("evidence/runtime-network/2026-11-13/x", None),
    ("docs/x.md", None),
]


@pytest.mark.parametrize(("path", "corpus"), CASES)
def test_corpus_identity_rule(path: str, corpus: str | None) -> None:
    """Each path is placed in the corpus that the rule names, or in none."""
    assert evidence_corpus.corpus_of(path) == corpus, path


def test_excluded_corpora_are_read_from_the_curation_file(tmp_path: Path) -> None:
    """Only corpora with the excluded disposition are returned."""
    document = {
        "schema_version": 1,
        "corpora": [
            {"path": "evidence/a/b/c", "disposition": "included"},
            {"path": "evidence/a/b/d", "disposition": "excluded"},
        ],
    }
    target = tmp_path / "curation.json"
    target.write_text(json.dumps(document), encoding="utf-8")
    assert evidence_corpus.load_excluded(target) == {"evidence/a/b/d"}, "excluded set"


def test_absent_curation_file_is_a_missing_input(tmp_path: Path) -> None:
    """A curation file that does not exist cannot be read."""
    with pytest.raises(MissingInputError, match="curation"):
        evidence_corpus.load_excluded(tmp_path / "curation.json")
