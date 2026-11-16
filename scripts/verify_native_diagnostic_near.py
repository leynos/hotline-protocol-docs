#!/usr/bin/env python3
"""Verify A11's fixed 303 near-boundary report and exact-reference cleanup."""

import json
import sys
from pathlib import Path

from native_diagnostic_existing_cases import NAME
from native_diagnostic_near_cases import (
    ACTIVE_CANCEL_IDS,
    ACTIVE_IDS,
    QUEUED_CANCEL_IDS,
    QUEUED_IDS,
)
from protocol_capture import decode_frame, verify_capture
from script_cli import UsageError, run
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_diagnostic,
    check_references,
    current_uid,
    require,
    section_witness,
)
from verify_native_diagnostic_existing import (
    semantic as existing_semantic,
)

NEAR_CASES = ("near-boundary", "postflight")
EXPECTED_BOUNDS = (24, 8)  # maximum references, maximum data sockets
EXPECTED_SETTINGS = (8, 8, 5)  # global download, per-client download, per-IP limits
PREDICTED_FIELD101_BYTES = 995  # field 101 length of the near report
EXTRA_WAITING_ROWS = 8  # waiting rows that the near report adds over report 140
WAITING_ROW_BYTES = 29  # bytes that one of those extra waiting rows adds
QUEUED_BEFORE_NEAR = 8  # queued requests sent before request 140
QUEUED_POSITIONS = 16  # queue positions that the near report must number
ACTIVE_REFERENCES = 8  # active references come before the queued ones in ``saved``


def sent_ids(report: dict) -> list[int]:
    """Return the transaction identifiers of the connection-a sends, in order.

    Parameters
    ----------
    report : dict
        The verified report, with its ``events``.

    Returns
    -------
    list[int]
        The identifiers of the sent frames, excluding the ``TRTP`` preamble.
    """
    ids = []
    for event in report["events"]:
        if event["event"] != "send" or event["connection"] != "a":
            continue
        raw = bytes.fromhex(event["hex"])
        if raw.startswith(b"TRTP"):
            continue
        ids.append(decode_frame(raw)["id"])
    return ids


def expected_ids() -> list[int]:
    """Return the transaction identifiers that the near-boundary plan must send.

    Returns
    -------
    list[int]
        The identifiers in the planned order.
    """
    return [
        1,
        10,
        *ACTIVE_IDS,
        *QUEUED_IDS[:QUEUED_BEFORE_NEAR],
        140,
        *QUEUED_IDS[QUEUED_BEFORE_NEAR:],
        141,
        *reversed(QUEUED_CANCEL_IDS),
        *reversed(ACTIVE_CANCEL_IDS),
        240,
    ]


def near_complete(diagnostics: dict, witnesses: dict) -> bool:
    """Return whether every witness is complete and the near report has its size.

    Parameters
    ----------
    diagnostics : dict
        The diagnostic of reports 140 and 141.
    witnesses : dict
        The witness of each reported 303 reply.

    Returns
    -------
    bool
        Whether the witnesses are complete, the field 101 length is predicted and the
        growth over report 140 is predicted.
    """
    near_bytes = diagnostics["141"]["field101_bytes"]
    delta = near_bytes - diagnostics["140"]["field101_bytes"]
    return (
        all(item["status"] == "complete" for item in witnesses.values())
        and near_bytes == PREDICTED_FIELD101_BYTES
        and delta == EXTRA_WAITING_ROWS * WAITING_ROW_BYTES
    )


def require_positions(positions: list[int]) -> None:
    """Check that the queue positions are the numbers 1 to ``QUEUED_POSITIONS``.

    Parameters
    ----------
    positions : list[int]
        The queue position of each queued reply, in request order.
    """
    require(positions == list(range(1, QUEUED_POSITIONS + 1)), "Queue positions differ")


def _check_plan(report: dict) -> None:
    """Read the plan of ``report`` and check its case, fixture, bounds and settings.

    Parameters
    ----------
    report : dict
        The verified report, with ``_plan_path`` naming its plan file.
    """
    plan = json.loads(report["_plan_path"].read_text())
    expectation = plan["expectation"]
    require(expectation["case"] == "near-boundary", "Wrong case")
    require(expectation["fixture_name_hex"] == NAME.hex(), "Wrong fixture")
    require(
        (expectation["maximum_references"], expectation["maximum_data_sockets"])
        == EXPECTED_BOUNDS,
        "Bounds differ",
    )
    require(
        (
            expectation["global_download_limit"],
            expectation["per_client_download_limit"],
            expectation["per_ip_limit"],
        )
        == EXPECTED_SETTINGS,
        "Settings differ",
    )


def _check_cancellations(report: dict, references: list[str]) -> None:
    """Check that each cancellation names the reference of the request it cancels.

    Parameters
    ----------
    report : dict
        The verified report.
    references : list[str]
        The hexadecimal references in request order, active requests first.
    """
    saved = [bytes.fromhex(value) for value in references]
    check_cancellations(
        report,
        {
            **{
                identifier: saved[ACTIVE_REFERENCES + index]
                for index, identifier in enumerate(QUEUED_CANCEL_IDS)
            },
            **{
                identifier: saved[index]
                for index, identifier in enumerate(ACTIVE_CANCEL_IDS)
            },
        },
    )


def semantic(report: dict) -> dict:
    """Judge the near-boundary case from its verified report.

    Parameters
    ----------
    report : dict
        The verified report, with ``_plan_path`` naming its plan file.

    Returns
    -------
    dict
        The result of the case, with its status and the observed growth.
    """
    require(report["status"] == "completed", "Capture incomplete")
    _check_plan(report)
    ids = sent_ids(report)
    require(len(ids) == len(set(ids)), "Duplicate request ID")
    require(ids == expected_ids(), "Request ID sequence differs")
    uid = current_uid(report)
    references = check_references(report, list(ACTIVE_IDS), list(QUEUED_IDS))
    require_positions(references["waiting_positions"])
    _check_cancellations(report, references["references"])
    diagnostics = {
        str(identifier): check_diagnostic(report, identifier, uid)
        for identifier in (140, 141, 240)
    }
    points = {140: (8, 8), 141: (8, 16), 240: (0, 0)}
    witnesses = {
        str(identifier): section_witness(
            bytes.fromhex(diagnostics[str(identifier)]["field101_hex"]), *counts
        )
        for identifier, counts in points.items()
    }
    near_bytes = diagnostics["141"]["field101_bytes"]
    delta = near_bytes - diagnostics["140"]["field101_bytes"]
    complete = near_complete(diagnostics, witnesses)
    return {
        "case": "near-boundary",
        "status": "verified" if complete else "incomplete-witness",
        **references,
        "diagnostics": diagnostics,
        "witnesses": witnesses,
        "predicted_field101_bytes": PREDICTED_FIELD101_BYTES,
        "observed_extra_waiting_bytes": delta,
    }


def verify_and_write(
    case: str, capture: str, *, output: str, a7_baseline: str | None = None
) -> None:
    """Verify one near-boundary or postflight capture and write its result.

    Parameters
    ----------
    case : str
        The case to check, ``"near-boundary"`` or ``"postflight"``.
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
    ValueError
        When the postflight case is given no baseline.
    """
    if case not in NEAR_CASES:
        choices = ", ".join(repr(name) for name in NEAR_CASES)
        message = f"argument case: invalid choice: {case!r} (choose from {choices})"
        raise UsageError(message)
    output_path = Path(output)
    if output_path.exists():
        sys.exit(f"Refusing existing output: {output_path}")
    report = verify_capture(Path(capture))
    report["_plan_path"] = Path(capture) / "plan.json"
    if case == "postflight":
        if a7_baseline is None:
            message = "A7 baseline required"
            raise ValueError(message)
        baseline = verify_capture(Path(a7_baseline))
        result = existing_semantic("postflight", report, baseline)
    else:
        result = semantic(report)
    output_path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"{case}: {result['status']}\n")
    if result["status"] != "verified":
        raise SystemExit(1)


def main() -> None:
    """Verify a near-boundary or postflight capture from the command line."""
    run(verify_and_write, __doc__)


if __name__ == "__main__":
    main()
