"""Structural assertions on the committed INV-SCRIPT goldens.

These read ``tests/goldens/`` and never run the inherited scripts; the logic
that wrote the goldens is tested in ``test_legacy_goldens.py``. Re-running the
scripts against the goldens is ``make goldens-check``.
"""

import re
import typing as typ
from pathlib import Path

import capture_goldens as cg
import golden_model as gm
import golden_recipes as gr
import pytest

REPO = Path(__file__).resolve().parents[1]
HEX = re.compile(r"[0-9a-f]{64}")


@pytest.fixture(scope="module")
def goldens() -> dict[str, dict[str, typ.Any]]:
    """Read the three committed goldens.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        Each golden document by oracle name.
    """
    return {name: gm.read_golden(REPO, f"{name}.json") for name in cg.ORACLES}


def test_golden_verifiers_cover_every_makefile_recipe(goldens: dict) -> None:
    """Every recipe line of both targets has one record; passing ones exit 0."""
    records = goldens["verifiers"]["records"]
    for target in gr.TARGETS:
        recorded = [k for k in records if k.startswith(f"{target}: ")]
        expected = [f"{target}: {line}" for line in gr.recipe_lines(REPO, target, None)]
        assert recorded == expected, target
    names = " ".join(records)
    corpora = set(re.findall(r"evidence/gap-remediation/[\w-]+/[\w-]+", names))
    assert len(corpora) >= 60, sorted(corpora)
    for corpus in corpora:
        assert any(corpus in key for key in records), corpus
    for key, record in records.items():
        assert HEX.fullmatch(record["output_sha256"]), key
        if record["target"] == "evidence-verify":
            assert record["exit_code"] == 0, key


def test_golden_known_red_entries_are_recorded_as_failing(goldens: dict) -> None:
    """The decision-D18 verifier fails, and so does its one inherited test."""
    records = goldens["verifiers"]["records"].values()
    red = [r for r in records if r["target"] == "evidence-verify-known-red"]
    assert len(red) == 1, red
    assert red[0]["exit_code"] != 0, red[0]
    reason = "capture gate source identity"
    assert reason in red[0]["last_line"], red[0]
    tests = goldens["tests"]["records"]
    errors = {k: v for k, v in tests.items() if v["outcome"] != "ok"}
    failing = [k for k in errors if k.endswith("test_original_corpus_replays")]
    assert len(failing) == 1, sorted(errors)
    assert reason in errors[failing[0]]["detail"], errors[failing[0]]


def test_golden_tests_record_the_inherited_suite(goldens: dict) -> None:
    """At least 758 tests are recorded, each with an outcome."""
    tests = goldens["tests"]["records"]
    assert len(tests) >= 758, len(tests)
    outcomes = [r["outcome"] for r in tests.values()]
    assert set(outcomes) <= {"ok", "error", "fail", "skipped"}, set(outcomes)
    assert outcomes.count("error") == 1, outcomes.count("error")


def test_golden_planners_account_for_every_planner_file(goldens: dict) -> None:
    """All 45 planner files have a role; each record emitted or says why not."""
    coverage = goldens["planners"]["coverage"]
    records = goldens["planners"]["records"]
    on_disk = {p.name for p in (REPO / "scripts").glob("*_cases.py")}
    assert set(coverage) == on_disk, set(coverage) ^ on_disk
    assert len(coverage) == 45, len(coverage)
    for key, record in records.items():
        assert record["status"] in {"emitted", "skipped"}, key
        if record["status"] == "skipped":
            assert record["reason"], key
            continue
        assert record["exit_code"] == 0, key
        assert record["files"], key
        digests = [f["sha256"] for f in record["files"].values()]
        assert all(HEX.fullmatch(d) for d in digests), key
    emitting = {key.split()[0] for key in records}
    direct = {f for f, role in coverage.items() if role in {"direct", "in-process"}}
    assert direct <= emitting, direct - emitting
