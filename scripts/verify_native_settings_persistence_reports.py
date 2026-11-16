"""Replay the A46 legacy and A48 planned-EOF phase reports of the corpus."""

import dataclasses as dc
import json
import tempfile
import typing as typ
from pathlib import Path

import native_settings_persistence as current_runner
from protocol_capture import ORACLE_SHA256, digest, verify_capture
from verify_native_settings_persistence_core import (
    A46_SOURCES,
    A48_SOURCES,
    Json,
    load_frozen,
    read_json,
    require,
)

if typ.TYPE_CHECKING:
    import types

LEGACY_STEPS = 64  # the legacy plan, which ends before its two EOF reads
LEGACY_ACTIONS = 66  # the legacy report, which ran them
LEGACY_GATES = 15
PLANNED_ACTIONS = 28
PLANNED_OBSERVATION_ACTIONS = 26
EOF_TIMEOUT = 720
EOF_ACTIONS = [(64, "subject"), (65, "main")]
EOF_CONNECTIONS = ("subject", "main")
PHASE_ONLY = "verified_phase_only"
GENERIC_REJECTION = "Incomplete plan reported as completed"
PLANNED_GATES = ["identity", "baseline-delivery", "baseline-pm"]


@dc.dataclass(frozen=True, slots=True)
class Legacy:
    """The retained A46 plan and report, as bytes and as parsed.

    Attributes
    ----------
    directory : pathlib.Path
        The capture directory.
    plan_raw : bytes
        The plan's bytes.
    report_raw : bytes
        The report's bytes.
    plan : dict[str, typing.Any]
        The parsed plan.
    report : dict[str, typing.Any]
        The parsed report.
    """

    directory: Path
    plan_raw: bytes
    report_raw: bytes
    plan: Json
    report: Json


def legacy_files(corpus: Path) -> Legacy:
    """Read the A46 capture, check its checksums and that it is the planned one.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    Legacy
        The plan and report.
    """
    directory = corpus / "phase1/phase1"
    plan_raw = (directory / "plan.json").read_bytes()
    report_raw = (directory / "report.json").read_bytes()
    checks = (directory / "checksums.sha256").read_text()
    require(
        checks == f"{digest(plan_raw)}  plan.json\n{digest(report_raw)}  report.json\n",
        "A46 raw checksums differ",
    )
    plan, report = json.loads(plan_raw), json.loads(report_raw)
    require(
        plan == read_json(corpus / "phase1/plans/phase1.json"),
        "A46 as-run plan differs",
    )
    return Legacy(directory, plan_raw, report_raw, plan, report)


def legacy_provenance(legacy: Legacy) -> None:
    """Check the legacy counts, provenance, oracle and EOF actions.

    Parameters
    ----------
    legacy : Legacy
        The A46 plan and report.
    """
    plan, report = legacy.plan, legacy.report
    require(
        len(plan["steps"]) == LEGACY_STEPS
        and report["completed_actions"] == LEGACY_ACTIONS
        and report["status"] == "completed",
        "A46 legacy 64+2 count differs",
    )
    require(
        report["plan_sha256"] == digest(legacy.plan_raw)
        and report["driver_sha256"] == A46_SOURCES["native_settings_persistence.py"],
        "A46 raw provenance differs",
    )
    require(
        report["oracle_sha256"] == plan["oracle_sha256"] == ORACLE_SHA256,
        "A46 oracle differs",
    )
    eof = [
        (event["action"], event["connection"])
        for event in report["events"]
        if event["event"] == "eof"
    ]
    require(eof == EOF_ACTIONS, "A46 legacy EOF actions differ")


def generic_rejection(directory: Path) -> None:
    """Check that the generic verifier still rejects the legacy plan as it did.

    Parameters
    ----------
    directory : pathlib.Path
        The legacy capture directory.

    Raises
    ------
    ValueError
        If the generic verifier accepts the legacy plan.
    """
    try:
        verify_capture(directory)
    except ValueError as error:
        require(str(error) == GENERIC_REJECTION, "A46 generic rejection changed")
    else:
        message = "A46 raw legacy plan must remain generically rejected"
        raise ValueError(message)


def frozen_runner(corpus: Path, plan: Json) -> types.ModuleType:
    """Load the frozen A46 generator and runner and check the plan against it.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    plan : dict[str, typing.Any]
        The A46 plan.

    Returns
    -------
    types.ModuleType
        The frozen runner, wired to the frozen generator.
    """
    old_cases = load_frozen(
        "a46_cases", corpus / "source/a46/native_settings_persistence_cases.py"
    )
    old_runner = load_frozen(
        "a46_runner", corpus / "source/a46/native_settings_persistence.py"
    )
    vars(old_runner)["cases"] = old_cases  # the runner calls the frozen generator
    require(
        plan
        == old_cases.plans(plan["environment"], plan["endpoints"]["control"]["port"])[
            "phase1"
        ],
        "A46 frozen generator differs",
    )
    return old_runner


def normalized_replay(legacy: Legacy) -> Json:
    """Replay the legacy capture with its two EOF reads added to the plan.

    This is a temporary normalized analysis only; the retained as-run plan and
    report stay untouched.

    Parameters
    ----------
    legacy : Legacy
        The A46 plan and report.

    Returns
    -------
    dict[str, typing.Any]
        The replayed report.
    """
    normal_plan = json.loads(legacy.plan_raw)
    normal_plan["steps"] += [
        {"op": "read_eof", "connection": name, "timeout": EOF_TIMEOUT}
        for name in EOF_CONNECTIONS
    ]
    normal_report = json.loads(legacy.report_raw)
    with tempfile.TemporaryDirectory() as temporary:
        derived = Path(temporary)
        normal_raw = (json.dumps(normal_plan) + "\n").encode()
        normal_report["plan_sha256"] = digest(normal_raw)
        normal_report_raw = (json.dumps(normal_report) + "\n").encode()
        (derived / "plan.json").write_bytes(normal_raw)
        (derived / "report.json").write_bytes(normal_report_raw)
        plan_line = f"{digest(normal_raw)}  plan.json\n"
        report_line = f"{digest(normal_report_raw)}  report.json\n"
        (derived / "checksums.sha256").write_text(plan_line + report_line)
        return verify_capture(derived)


def legacy_semantic(corpus: Path, legacy: Legacy, runner: types.ModuleType) -> Json:
    """Check the legacy gates and the parent's independent verification.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    legacy : Legacy
        The A46 plan and report.
    runner : types.ModuleType
        The frozen A46 runner.

    Returns
    -------
    dict[str, typing.Any]
        The semantic result of the frozen runner.
    """
    semantic = runner.semantic(legacy.report, legacy.plan)
    require(
        semantic["status"] == PHASE_ONLY and len(semantic["gates"]) == LEGACY_GATES,
        "A46 legacy semantic gates differ",
    )
    parent = read_json(corpus / "baseline/a46-parent-verification.json")
    require(
        parent["raw_checksums_frames_streams_verified"]
        and parent["gates"] == semantic["gates"],
        "A46 independent replay differs",
    )
    return semantic


def legacy_report(corpus: Path) -> tuple[Json, Json, Json]:
    """Replay the A46 legacy phase and read its semantics.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    tuple[dict, dict, dict]
        The plan, the report and the semantic result.
    """
    legacy = legacy_files(corpus)
    legacy_provenance(legacy)
    generic_rejection(legacy.directory)
    runner = frozen_runner(corpus, legacy.plan)
    replay = normalized_replay(legacy)
    require(
        replay["frames"] == legacy.report["frames"]
        and replay["streams"] == legacy.report["streams"],
        "A46 raw frame/stream replay differs",
    )
    semantic = legacy_semantic(corpus, legacy, runner)
    return legacy.plan, legacy.report, semantic


def planned_report(corpus: Path) -> tuple[Json, Json, Json]:
    """Replay the A48 planned-EOF phase and read its semantics.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    tuple[dict, dict, dict]
        The plan, the report and the semantic result.
    """
    directory = corpus / "phase2/phase2"
    plan = read_json(directory / "plan.json")
    report = verify_capture(directory)
    require(
        plan == read_json(corpus / "phase2/plans/phase2.json"),
        "A48 as-run plan differs",
    )
    require(
        len(plan["steps"]) == report["completed_actions"] == PLANNED_ACTIONS,
        "A48 planned EOF count differs",
    )
    require(
        plan["expectation"]["observation_actions"] == PLANNED_OBSERVATION_ACTIONS,
        "A48 observation boundary differs",
    )
    require(
        report["driver_sha256"] == A48_SOURCES["native_settings_persistence.py"],
        "A48 driver differs",
    )
    semantic = current_runner.semantic(report, plan)
    require(
        semantic["status"] == PHASE_ONLY and semantic["gates"] == PLANNED_GATES,
        "A48 semantic gates differ",
    )
    return plan, report, semantic
