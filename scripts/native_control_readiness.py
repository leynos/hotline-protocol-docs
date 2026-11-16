#!/usr/bin/env python3
"""Prepare and gate one disposable native ban-control capture.

The gates live in the modules of ``CAPTURE_MODULES`` and every name they define
stays importable from here. The report that ``run_guarded_ban`` writes records
which scripts made it (decision D31): ``driver_sha256`` is the digest of the
modules of ``CAPTURE_MODULES`` and ``driver_identity`` holds the commit and the
hash of each. A report made before that decision holds the hash of this one file
in ``driver_sha256``.

Command lines::

    native_control_readiness.py prepare --runtime-record F --port N --output D
    native_control_readiness.py run --plans D --binary F --capture-ready F --output D
"""

import functools
import json
import sys
import typing as typ
from pathlib import Path

import native_ban_control_cases as cases
from native_control_readiness_ban import (
    BAN_TEXT,
    ORIGINAL_ACCOUNTS,
    after,
    outcome,
    probe,
    target_gate,
)
from native_control_readiness_gates import (
    BASELINE_FIELDS,
    field_digest,
    fields,
    guarded_account,
    login_gate,
    readiness,
)
from native_control_readiness_live import (
    capture_gate,
    plan_gate,
    require_controller_uid,
)
from native_control_readiness_run import execute_ban_step, run_ban
from protocol_capture import run_plan
from script_cli import UsageError, run
from verify_native_core import require

if typ.TYPE_CHECKING:
    import collections.abc as cabc

# The scripts that make this capture, in the fixed order of its identity digest.
CAPTURE_MODULES = (
    "native_control_readiness.py",
    "native_control_readiness_ban.py",
    "native_control_readiness_gates.py",
    "native_control_readiness_live.py",
    "native_control_readiness_run.py",
)

type Report = dict[str, typ.Any]

PREPARE_OPTIONS = ("runtime_record", "port", "output")
RUN_OPTIONS = ("plans", "binary", "capture_ready", "output")

__all__ = [
    "BAN_TEXT",
    "BASELINE_FIELDS",
    "CAPTURE_MODULES",
    "ORIGINAL_ACCOUNTS",
    "after",
    "capture_gate",
    "execute_ban_step",
    "field_digest",
    "fields",
    "guarded_account",
    "login_gate",
    "main",
    "outcome",
    "plan_gate",
    "probe",
    "readiness",
    "require_controller_uid",
    "run_guarded_ban",
    "target_gate",
]


def run_guarded_ban(plan_path: Path, binary: Path, output: Path) -> Report:
    """Run the ban plan, gating the 110 request, and write its capture.

    Parameters
    ----------
    plan_path : pathlib.Path
        The ban plan.
    binary : pathlib.Path
        The oracle binary, which must be the one that is recorded.
    output : pathlib.Path
        A directory that must not exist yet.

    Returns
    -------
    dict[str, typing.Any]
        The report that was written.
    """
    return run_ban(plan_path, binary, output, CAPTURE_MODULES)


def prepare(runtime_record: Path, port: int, output: Path) -> None:
    """Write the five plans and the digest of each.

    Parameters
    ----------
    runtime_record : pathlib.Path
        The runtime record, a JSON file.
    port : int
        The control port.
    output : pathlib.Path
        The plan directory.
    """
    result = cases.write_plans(output, json.loads(runtime_record.read_text()), port)
    (output / "source-hashes.json").write_text(json.dumps(result, indent=2) + "\n")


def _stages() -> list[tuple[str, cabc.Callable[[Report], None]]]:
    """List the stages of a live run with the gate that each report must pass.

    Returns
    -------
    list[tuple[str, collections.abc.Callable[[dict[str, typing.Any]], None]]]
        The stage names, in order, and their gates.
    """
    return [
        ("readiness", readiness),
        ("guard", functools.partial(guarded_account, absent=True)),
        ("seed", functools.partial(guarded_account, absent=False)),
        ("ban", outcome),
        ("probe", probe),
    ]


def _run_stage(
    name: str, receipt: dict[str, typ.Any], paths: tuple[Path, Path, Path]
) -> Report:
    """Run one stage after checking the receipt and the plan's emulator.

    Parameters
    ----------
    name : str
        The stage.
    receipt : dict[str, typing.Any]
        The capture-ready receipt.
    paths : tuple[pathlib.Path, pathlib.Path, pathlib.Path]
        The plan directory, the binary and the output directory.

    Returns
    -------
    dict[str, typing.Any]
        The stage's report.
    """
    plans, binary, output = paths
    capture_gate(receipt)
    plan = plans / f"{name}.json"
    planned = json.loads(plan.read_text())
    require(
        planned["environment"].get("emulator_pid") == receipt["emulator_pid"],
        "Plan/actual emulator PID mismatch",
    )
    destination = output / name
    if name == "ban":
        return run_guarded_ban(plan, binary, destination)
    return run_plan(plan, binary, destination)


def live_run(plans: Path, binary: Path, capture_ready: Path, output: Path) -> None:
    """Run the five stages in order, gating each report before the next stage.

    Parameters
    ----------
    plans : pathlib.Path
        The plan directory.
    binary : pathlib.Path
        The oracle binary.
    capture_ready : pathlib.Path
        The capture-ready receipt.
    output : pathlib.Path
        A directory that must not exist yet.
    """
    require_controller_uid()
    receipt = json.loads(capture_ready.read_text())
    capture_gate(receipt)
    plan_gate(plans, receipt["emulator_pid"])
    output.mkdir(parents=True, exist_ok=False)
    for name, gate in _stages():
        gate(_run_stage(name, receipt, (plans, binary, output)))


def _chosen(
    mode: str, given: cabc.Mapping[str, object], wanted: tuple[str, ...]
) -> dict[str, typ.Any]:
    """Require exactly the options that a mode takes.

    Parameters
    ----------
    mode : str
        The mode, for the message.
    given : collections.abc.Mapping[str, object]
        Every option of the command, with ``None`` for those not given.
    wanted : tuple[str, ...]
        The options that the mode takes.

    Returns
    -------
    dict[str, typing.Any]
        The options of the mode.

    Raises
    ------
    UsageError
        If an option of the mode is missing or one of another mode is given.
    """
    missing = [name for name in wanted if given[name] is None]
    stray = [
        name
        for name, value in given.items()
        if value is not None and name not in wanted
    ]
    if missing or stray:
        message = f"{mode}: needs {wanted}; missing {missing}, not accepted {stray}"
        raise UsageError(message)
    return {name: given[name] for name in wanted}


def command(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # one argument for each option of the two modes
    mode: typ.Literal["prepare", "run"],
    *,
    runtime_record: str | None = None,
    port: int | None = None,
    plans: str | None = None,
    binary: str | None = None,
    capture_ready: str | None = None,
    output: str | None = None,
) -> None:
    """Prepare the plans, or run a gated capture against a live emulator.

    Parameters
    ----------
    mode
        ``prepare`` writes the plans; ``run`` runs them.
    runtime_record
        The runtime record (``prepare``).
    port
        The control port (``prepare``).
    plans
        The plan directory (``run``).
    binary
        The oracle binary (``run``).
    capture_ready
        The capture-ready receipt (``run``).
    output
        The output directory.
    """
    given = {
        "runtime_record": runtime_record,
        "port": port,
        "plans": plans,
        "binary": binary,
        "capture_ready": capture_ready,
        "output": output,
    }
    if mode == "prepare":
        chosen = _chosen(mode, given, PREPARE_OPTIONS)
        prepare(Path(chosen["runtime_record"]), chosen["port"], Path(chosen["output"]))
    else:
        chosen = _chosen(mode, given, RUN_OPTIONS)
        live_run(
            Path(chosen["plans"]),
            Path(chosen["binary"]),
            Path(chosen["capture_ready"]),
            Path(chosen["output"]),
        )


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(command, __doc__, sys.argv[1:])
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
