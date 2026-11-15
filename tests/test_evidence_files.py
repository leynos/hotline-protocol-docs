"""Tests for finding evidence citations in the text of citing files."""

import evidence_files
import pytest


@pytest.mark.parametrize(
    ("text", "expected"),
    [
        pytest.param(
            b"see [x](../mothra/evidence/a/b/c.json) and `evidence/d/e`.",
            {"evidence/a/b/c.json", "evidence/d/e"},
            id="link target and bare path",
        ),
        pytest.param(
            b'--original "$agreement_evidence/original-agreement.data"',
            set(),
            id="shell variable ending in evidence",
        ),
        pytest.param(
            b"counterevidence/x and my_evidence/y",
            set(),
            id="longer word ending in evidence",
        ),
        pytest.param(
            b"[guide](../native-evidence/recreating-evidence.md)",
            set(),
            id="directory name ending in -evidence",
        ),
        pytest.param(
            b"(evidence/a/b) 'evidence/c/d'",
            {"evidence/a/b", "evidence/c/d"},
            id="after punctuation",
        ),
    ],
)
def test_cited_paths_match_whole_path_names_only(
    text: bytes, expected: set[str]
) -> None:
    """A citation starts at ``evidence/`` only when that begins a path name."""
    found = evidence_files.cited_paths(text)
    assert found == expected, f"expected {expected}, found {found}"
