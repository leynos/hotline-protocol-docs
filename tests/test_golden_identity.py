"""Test that the planner oracle ignores what a capture identity records per commit.

A planner that records the identity of its scripts (decision D31) writes the
commit, the files that differ from it and the digest of the set. None of those
is the same in two runs of the same plan, so the normaliser replaces them, and
leaves every other plan as it was.
"""

import json
import typing as typ

import golden_model as gm
import pytest

if typ.TYPE_CHECKING:
    from pathlib import Path

OWN = "a1" * 32
OTHER = "b2" * 32


def record(commit: str | None, dirty: list[str], digest: str) -> dict:
    """Build a capture identity record as ``capture_identity`` makes one.

    Returns
    -------
    dict
        The record, with one file whose hash is the digest of a script.
    """
    return {
        "schema_version": 1,
        "commit": commit,
        "dirty": dirty,
        "files": [{"path": "scripts/run.py", "sha256": OWN}],
        "digest": digest,
    }


def hashes(
    commit: str | None, dirty: list[str], digest: str, *, indent: int | None
) -> bytes:
    """Write a ``source-hashes.json`` that holds one identity record.

    Returns
    -------
    bytes
        The file, whose old field also holds the digest of the set.
    """
    value = {
        "plan.json": OTHER,
        "run.py": digest,
        "run_identity": record(commit, dirty, digest),
    }
    return (json.dumps(value, indent=indent) + "\n").encode()


@pytest.fixture
def norm(tmp_path: Path) -> gm.Normaliser:
    """Build a normaliser that knows one script digest.

    Returns
    -------
    golden_model.Normaliser
        The normaliser.
    """
    return gm.Normaliser(tmp_path, tmp_path, {OWN: "run.py"})


@pytest.mark.parametrize("indent", [None, 2])
def test_two_commits_and_two_digests_normalise_alike(
    norm: gm.Normaliser, indent: int | None
) -> None:
    """The commit, the dirty list and the digest of the set do not show."""
    first = hashes("c" * 40, [], "d" * 64, indent=indent)
    second = hashes(
        "e" * 40, ["scripts/run.py", "scripts/helper.py"], "f" * 64, indent=indent
    )
    assert norm.plan(first) == norm.plan(second), "the normalised plans differ"


def test_a_missing_commit_normalises_like_a_commit(norm: gm.Normaliser) -> None:
    """A record made outside Git normalises like one made inside it."""
    assert norm.plan(hashes(None, ["scripts/run.py"], "d" * 64, indent=None)) == (
        norm.plan(hashes("c" * 40, [], "e" * 64, indent=None))
    ), "the commit is still visible"


def test_the_size_does_not_depend_on_the_dirty_list(norm: gm.Normaliser) -> None:
    """The settled bytes have one length, whatever files differed from the commit."""
    clean = hashes("c" * 40, [], "d" * 64, indent=None)
    dirty = hashes("c" * 40, ["scripts/run.py"], "d" * 64, indent=None)
    assert len(gm.settle(clean)) == len(gm.settle(dirty)), "the sizes differ"


def test_the_listed_script_hash_is_still_named(norm: gm.Normaliser) -> None:
    """The hash of a listed script still becomes its name, and the other hash stays."""
    content, names = norm.plan(hashes("c" * 40, [], "d" * 64, indent=None))
    assert names == ["run.py"], names
    assert b"{scripts/run.py}" in content, content
    assert OTHER.encode() in content, "an unrelated hash was changed"


def test_a_plan_without_an_identity_is_not_touched(norm: gm.Normaliser) -> None:
    """Text that holds no identity record settles to itself."""
    raw = json.dumps({"plan.json": OTHER, "digest": "9" * 64, "commit": "x"}).encode()
    assert gm.settle(raw) == raw, "a plan with no record was changed"
