"""Gates that tie the frozen sources, the plan and the run to their approvals."""

import typing as typ
from pathlib import Path

from verify_native_path_fields_constants import (
    APPROVED_MODULES,
    CASE_PORT,
    CASES,
    CONTROL,
    HELPER_MODULES,
    PLAN,
    PREWRITTEN_SCRIPTS,
)
from verify_native_path_fields_core import need, pins, read, sha

if typ.TYPE_CHECKING:
    import types


def _closure(epoch: Path, prep: Path, freeze: dict) -> None:
    """Check the approved closure, its helpers and each frozen byte."""
    proposed = read(prep / "proposed-source-closure.json")["hashes"]
    approved = pins(prep / "approved-source-closure.sha256")
    need(
        len(proposed) == len(freeze["hashes"]) == len(approved) == APPROVED_MODULES
        and approved == {f"scripts/{name}": digest for name, digest in proposed.items()}
        and freeze["hashes"] == proposed,
        "Approved 37-module closure differs",
    )
    for name, digest in proposed.items():
        need(
            sha(epoch / "sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Frozen/proposed source differs: {name}",
        )


def _helpers(epoch: Path, prep: Path, freeze: dict) -> None:
    """Check the approved helper modules against the frozen helper hashes."""
    helpers = pins(prep / "approved-helpers.sha256")
    need(
        len(helpers) == HELPER_MODULES
        and freeze["helper_hashes"]
        == {Path(name).name: digest for name, digest in helpers.items()},
        "Helper approval differs",
    )
    for name, digest in freeze["helper_hashes"].items():
        need(
            sha(epoch / "helper-sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Frozen helper differs: {name}",
        )


def _owned(control: types.ModuleType, cases: types.ModuleType, prep: Path) -> None:
    """Check the two owned path-field sources, loaded from their frozen copies."""
    owned = pins(prep / "approved-path-fields-sources.sha256")
    need(
        owned
        == {
            "scripts/native_path_fields_cases.py": CASES,
            "scripts/native_path_fields_control.py": CONTROL,
        }
        and sha(Path(typ.cast("str", control.__file__))) == CONTROL
        and sha(Path(typ.cast("str", cases.__file__))) == CASES,
        "Approved path source differs",
    )


def _prewritten(prep: Path) -> None:
    """Check the prewritten preparation scripts against their pins."""
    scripts = pins(prep / "script-SHA256SUMS")
    need(len(scripts) == PREWRITTEN_SCRIPTS, "Prewritten script inventory differs")
    for name, digest in scripts.items():
        need(
            name.startswith("state/native-sessions/native-path-fields-preparation-01/")
            and sha(prep / "scripts" / Path(name).name) == digest,
            "Prewritten script differs",
        )


def _as_run(epoch: Path, cases: types.ModuleType) -> dict:
    """Check the as-run plan against the pinned digest and the planner's output.

    Returns
    -------
    dict
        The plan of the case.
    """
    plan_path = epoch / "path-fields-plan/plan.json"
    plan = read(plan_path)
    need(
        sha(plan_path) == PLAN
        and plan == cases.source_plan(plan["environment"], CASE_PORT)
        and read(epoch / "path-fields-plan/source-hashes.json")
        == {
            "plan.json": PLAN,
            "native_path_fields_cases.py": CASES,
            "native_path_fields_control.py": CONTROL,
        }
        and sha(epoch / "coordinator/plan.json") == PLAN
        and sha(epoch / "parent-regenerated-plan/plan.json") == PLAN,
        "As-run plan/source differs",
    )
    need(
        read(epoch / "source-prerun-check.json")["status"]
        == "all_frozen_sources_match_current",
        "Pre-run source check missing",
    )
    return plan


def source_identity(corpus: Path, modules: tuple[types.ModuleType, ...]) -> dict:
    """Gate the approved closure, the owned sources and the as-run plan.

    Returns
    -------
    dict
        The plan of the case, as the as-run gate authenticated it.
    """
    control, cases, _, _, _ = modules
    epoch, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    freeze = read(epoch / "source-freeze.json")
    _closure(epoch, prep, freeze)
    _helpers(epoch, prep, freeze)
    _owned(control, cases, prep)
    _prewritten(prep)
    return _as_run(epoch, cases)
