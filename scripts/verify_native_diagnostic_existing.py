#!/usr/bin/env python3
"""Check bounded A8 303 load reports without imposing exact prose parity."""

import json
import sys
from pathlib import Path

from native_diagnostic_existing_cases import CASES, NAME
from native_wire_names import FIELD_ERROR_TEXT, FIELD_USER_RECORD
from protocol_capture import verify_capture
from script_cli import UsageError, run
from verify_native_diagnostic_checks import (
    FORK_BYTES,
    STREAM_BYTES,
    UID_BYTES,
    check_cancellations,
    check_diagnostic,
    check_references,
    current_uid,
    reply,
    require,
    values,
)
from verify_native_diagnostic_witness import HEADINGS, section_witness

# The names below stay importable from this module. The checks live in
# verify_native_diagnostic_checks and the witness in verify_native_diagnostic_witness.
# verify_native_diagnostic_near re-uses require, check_cancellations, check_diagnostic,
# check_references, current_uid, section_witness and semantic from here. The
# evidence verifiers verify_packets.py, verify_density.py and verify_partial.py
# import semantic (verify_partial.py also values), and scripts/verify_native_pm_
# readback.py and the scripts/test_native_diagnostic_*.py tests import the rest.
__all__ = [
    "FORK_BYTES",
    "HEADINGS",
    "STREAM_BYTES",
    "check_cancellations",
    "check_diagnostic",
    "check_references",
    "current_uid",
    "main",
    "reply",
    "require",
    "section_witness",
    "semantic",
    "values",
]


def _postflight(case: str, report: dict, baseline: dict | None) -> dict:
    """Check the postflight case against the A7 baseline and its 303 reply.

    Parameters
    ----------
    case : str
        The case name, copied into the result.
    report : dict
        The verified report of the postflight capture.
    baseline : dict | None
        The verified A7 baseline, which the postflight case must have.

    Returns
    -------
    dict
        The result with its status and the diagnostic and witness of reply 14.

    Raises
    ------
    ValueError
        If there is no baseline.
    """
    if baseline is None:
        message = "Missing A7 baseline"
        raise ValueError(message)
    require(
        reply(report, 10)["fields"] == reply(baseline, 10)["fields"],
        "Account baseline changed",
    )
    require(
        reply(report, 11)["fields"] == reply(baseline, 11)["fields"],
        "Files baseline changed",
    )
    require(
        reply(report, 12)["fields"] == reply(baseline, 12)["fields"],
        "Fixture metadata changed",
    )
    roster = reply(report, 13)["fields"]
    require(
        len(roster) == 1 and roster[0]["id"] == FIELD_USER_RECORD,
        "Ambiguous postflight roster",
    )
    uid = bytes.fromhex(roster[0]["hex"])[:UID_BYTES]
    diagnostic = check_diagnostic(report, 14, uid)
    witness = section_witness(bytes.fromhex(diagnostic["field101_hex"]), 0, 0)
    return {
        "case": case,
        "status": "verified"
        if witness["status"] == "complete"
        else "incomplete-witness",
        "diagnostics": {"14": diagnostic},
        "witnesses": {"14": witness},
    }


def _one_active_one_queued(case: str, report: dict, uid: bytes) -> dict:
    """Check the one-active-one-queued case, its denial control and its cancellations.

    Parameters
    ----------
    case : str
        The case name, copied into the result.
    report : dict
        The verified report of the capture.
    uid : bytes
        The account identifier of the current roster.

    Returns
    -------
    dict
        The result with its status, references, diagnostics and witnesses.
    """
    references = check_references(report, [11], [12])
    diagnostics = {str(i): check_diagnostic(report, i, uid) for i in [13, 17]}
    denied = values(reply(report, 14, success=False))
    require(
        reply(report, 14, success=False)["error"] == 1
        and set(denied) == {FIELD_ERROR_TEXT},
        "Missing-target control differs",
    )
    saved = [bytes.fromhex(value) for value in references["references"]]
    check_cancellations(report, {15: saved[1], 16: saved[0]})
    witnesses = {
        "13": section_witness(bytes.fromhex(diagnostics["13"]["field101_hex"]), 1, 1),
        "17": section_witness(bytes.fromhex(diagnostics["17"]["field101_hex"]), 0, 0),
    }
    complete = all(value["status"] == "complete" for value in witnesses.values())
    return {
        "case": case,
        "status": "verified" if complete else "incomplete-witness",
        **references,
        "diagnostics": diagnostics,
        "witnesses": witnesses,
    }


def _density(case: str, report: dict, uid: bytes) -> dict:
    """Check the density case: its references, cancellations and density witnesses.

    Parameters
    ----------
    case : str
        The case name, copied into the result.
    report : dict
        The verified report of the capture.
    uid : bytes
        The account identifier of the current roster.

    Returns
    -------
    dict
        The result with its status, references, diagnostics and witnesses.
    """
    references = check_references(report, list(range(20, 28)), list(range(40, 48)))
    diagnostics = {str(i): check_diagnostic(report, i, uid) for i in [35, 60, 61, 90]}
    saved = [bytes.fromhex(value) for value in references["references"]]
    check_cancellations(
        report,
        {
            **{70 + index: saved[8 + index] for index in range(8)},
            **{80 + index: saved[index] for index in range(8)},
        },
    )
    points = {35: (4, 0), 60: (8, 4), 61: (8, 8), 90: (0, 0)}
    witnesses = {
        str(identifier): section_witness(
            bytes.fromhex(diagnostics[str(identifier)]["field101_hex"]), *counts
        )
        for identifier, counts in points.items()
    }
    complete = all(value["status"] == "complete" for value in witnesses.values())
    return {
        "case": case,
        "status": "verified" if complete else "incomplete-witness",
        **references,
        "diagnostics": diagnostics,
        "witnesses": witnesses,
    }


def semantic(case: str, report: dict, baseline: dict | None = None) -> dict:
    """Judge one existing-diagnostic case from its verified report.

    Parameters
    ----------
    case : str
        The case named by the plan, which must match.
    report : dict
        The verified report, with ``_plan_path`` naming its plan file.
    baseline : dict | None
        The verified A7 baseline, required by the postflight case.

    Returns
    -------
    dict
        The result of the case, with its status.
    """
    require(report["status"] == "completed", "Capture incomplete")
    plan = json.loads(report["_plan_path"].read_text())
    require(plan["expectation"]["case"] == case, "Case differs")
    require(plan["expectation"]["fixture_name_hex"] == NAME.hex(), "Fixture differs")
    if case == "postflight":
        return _postflight(case, report, baseline)
    uid = current_uid(report)
    if case == "one-active-one-queued":
        return _one_active_one_queued(case, report, uid)
    require(case == "density", "Unknown case")
    return _density(case, report, uid)


def verify_and_write(
    case: str, capture: str, *, output: str, a7_baseline: str | None = None
) -> None:
    """Verify one existing-diagnostic capture and write its result to ``output``.

    Parameters
    ----------
    case : str
        The case to check, one of the keys of ``CASES``.
    capture : str
        The capture directory, holding ``plan.json`` and ``report.json``.
    output : str
        The file to write; it must not exist yet.
    a7_baseline : str | None
        The A7 baseline capture directory, required by the postflight case.

    Raises
    ------
    UsageError
        When ``case`` is not one of the cases.
    SystemExit
        When the output exists, or when the status is not ``"verified"``.
    """
    if case not in CASES:
        choices = ", ".join(repr(name) for name in CASES)
        message = f"argument case: invalid choice: {case!r} (choose from {choices})"
        raise UsageError(message)
    report = verify_capture(Path(capture))
    report["_plan_path"] = Path(capture) / "plan.json"
    baseline = verify_capture(Path(a7_baseline)) if a7_baseline is not None else None
    result = semantic(case, report, baseline)
    output_path = Path(output)
    if output_path.exists():
        sys.exit(f"Refusing existing output: {output_path}")
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"{case}: {result['status']}\n")
    if result["status"] != "verified":
        raise SystemExit(1)


def main() -> None:
    """Verify an existing-diagnostic capture from the command line."""
    run(verify_and_write, __doc__)


if __name__ == "__main__":
    main()
