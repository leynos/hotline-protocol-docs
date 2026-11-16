"""Checks that the frozen sources, the producer and the schedule are as recorded."""

import typing as typ

from verify_native_liveness_checks import Report, need, read, sha
from verify_native_liveness_pins import CASES, DATA, PLAN, RUNNER

if typ.TYPE_CHECKING:
    from pathlib import Path

DURATION_SECONDS = 135  # the length of the finite schedule, in seconds
OPERATION_COUNT = 47  # the number of operations in the finite schedule


def source_gate(corpus: Path, modules: tuple[typ.Any, ...]) -> Report:
    """Check the frozen sources, the producer and the plan, and return the plan.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    modules : tuple[typing.Any, ...]
        The frozen modules, as yielded by ``frozen``.

    Returns
    -------
    dict[str, typing.Any]
        The generated plan.
    """
    raw = corpus / "raw"
    _, cases, _, capture, _ = modules
    freeze = read(raw / "source-freeze.json")
    closure = read(corpus / "sources/dependency-closure.json")
    need(
        closure["module_count"] == len(closure["hashes"])
        and set(freeze["hashes"]).issubset({
            f"{name}.py" for name in closure["hashes"]
        }),
        "Frozen source closure differs",
    )
    for name, digest in closure["hashes"].items():
        need(
            sha(corpus / "sources/protocol" / f"{name}.py") == digest,
            f"Frozen dependency differs: {name}",
        )
    for name, digest in freeze["hashes"].items():
        need(
            sha(raw / "sources" / name) == digest
            and sha(corpus / "sources/protocol" / name) == digest,
            f"As-run source differs: {name}",
        )
    need(
        sha(corpus / "sources/protocol/native_liveness_cases.py") == CASES
        and sha(corpus / "sources/protocol/native_liveness_control.py") == RUNNER
        and sha(raw / "liveness-plan/plan.json") == PLAN
        and read(raw / "liveness-plan/source-hashes.json") == {"plan.json": PLAN},
        "B75 producer, runner or plan differs",
    )
    plan = read(raw / "liveness-plan/plan.json")
    need(
        plan == cases.source_plan(plan["environment"], cases.PORT)
        and plan["oracle_sha256"] == capture.ORACLE_SHA256 == DATA
        and plan["schedule"]["duration_seconds"] == DURATION_SECONDS
        and len(plan["schedule"]["operations"]) == OPERATION_COUNT,
        "Generated finite schedule differs",
    )
    need(
        read(raw / "coordinator/plan.json") == plan,
        "As-run coordinator plan differs",
    )
    return plan
