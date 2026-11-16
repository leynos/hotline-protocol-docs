#!/usr/bin/env python3
"""Prepare bounded, two-session native private-message observations."""

import json
import typing as typ
from pathlib import Path

from native_pm_baseline import (
    BASELINE_ENDPOINTS,
    BASELINE_SHA256,
    FULL_STREAM_BYTES,
    IDENTITY_KEYS,
    check_baseline_structure,
    load_baseline,
)
from native_pm_observe import CASES, MAIN, PEER, QUOTE, Case, observe
from native_pm_steps import barrier, settings, variable_message
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import UsageError, run

type Json = dict[str, typ.Any]

# The step builders, the case table and the baseline names live in their own
# modules and stay importable from here, as the verifiers and the other planners
# import them from this module.
__all__ = [
    "BASELINE_SHA256",
    "CASES",
    "FULL_STREAM_BYTES",
    "MAIN",
    "PEER",
    "QUOTE",
    "Case",
    "barrier",
    "check_baseline_structure",
    "load_baseline",
    "main",
    "observe",
    "plans",
    "settings",
    "variable_message",
]


def plans(runtime: Json, baseline_raw: bytes) -> dict[str, Json]:
    """Prepare the preflight, observation and postflight plans.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The runtime record; its identity fields must equal the baseline's.
    baseline_raw : bytes
        The baseline plan's bytes.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The three plans, the baseline being its own preflight and postflight.

    Raises
    ------
    ValueError
        If the baseline fails :func:`load_baseline` or the runtime identity
        differs from the baseline's.
    """
    baseline = load_baseline(baseline_raw)
    if any(
        runtime.get(key) != baseline["environment"].get(key) for key in IDENTITY_KEYS
    ):
        message = "Runtime identity differs from immutable A7 baseline"
        raise ValueError(message)
    observed = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated A26 PM preparation; live lease required",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-044"],
        "environment": runtime,
        "endpoints": {"control": dict(BASELINE_ENDPOINTS["control"])},
        "steps": observe(),
        "expectation": {
            "case": "observe",
            "cases": list(CASES),
            "pm_request_count": len(CASES),
            "baseline_plan_sha256": BASELINE_SHA256,
        },
    }
    validate_plan(observed)
    return {"preflight": baseline, "observe": observed, "postflight": baseline}


def command(*, runtime_record: str, baseline_plan: str, output: str) -> None:
    """Write the preflight, observe and postflight plans to a new directory.

    Parameters
    ----------
    runtime_record
        The JSON record of the running emulator.
    baseline_plan
        The A7 baseline plan.
    output
        The directory to create; it must not exist.

    Raises
    ------
    UsageError
        If the output directory exists.
    """
    target = Path(output)
    if target.exists():
        message = "Refusing existing output"
        raise UsageError(message)
    baseline_raw = Path(baseline_plan).read_bytes()
    prepared = plans(
        json.loads(Path(runtime_record).read_text(encoding="utf-8")), baseline_raw
    )
    target.mkdir(parents=True)
    for label, plan in prepared.items():
        (target / f"{label}.json").write_bytes(
            baseline_raw
            if label != "observe"
            else (json.dumps(plan, indent=2) + "\n").encode()
        )


def main() -> None:
    """Run the command line; a successful run returns instead of exiting.

    Raises
    ------
    SystemExit
        With a non-zero status when the command line cannot be used.
    """
    try:
        run(command, __doc__)
    except SystemExit as stop:
        if stop.code:  # the command line library exits with 0 on success
            raise


if __name__ == "__main__":
    main()
