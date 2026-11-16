#!/usr/bin/env python3
"""Prepare the fixed, unexecuted 8-active/16-waiting native 303 case."""

import json
import sys
from pathlib import Path

from native_diagnostic_existing_cases import NAME, diagnostic, request, roster
from native_plan import close
from native_queue_cases import attach, cancel, session
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import run

ACTIVE_IDS = tuple(range(100, 108))
QUEUED_IDS = tuple(range(120, 136))
QUEUED_CANCEL_IDS = tuple(range(200, 216))
ACTIVE_CANCEL_IDS = tuple(range(220, 228))
MAX_REFERENCES = 24
MAX_DATA_SOCKETS = 8
DIAGNOSTIC_QUEUED_INDEX = 7  # the 303 probe follows the eighth waiting reference
CONTROL_PORT = 15500
DATA_PORT = 15501
PER_IP_LIMIT = 5


def near() -> list[dict]:
    """Plan the active references, waiting references, cancellations and probes.

    Returns
    -------
    list[dict]
        The steps of the near-boundary case, in order.
    """
    steps = session("a") + roster(10)
    for index, identifier in enumerate(ACTIVE_IDS):
        variable = f"active{index}"
        steps += request(identifier, variable) + attach(variable)
    for index, identifier in enumerate(QUEUED_IDS):
        steps += request(identifier, f"queued{index}")
        if index == DIAGNOSTIC_QUEUED_INDEX:
            steps += diagnostic(140)
    steps += diagnostic(141)
    for index in reversed(range(len(QUEUED_IDS))):
        steps += cancel("a", QUEUED_CANCEL_IDS[index], f"queued{index}")
    for index in reversed(range(len(ACTIVE_IDS))):
        variable = f"active{index}"
        steps += [*cancel("a", ACTIVE_CANCEL_IDS[index], variable), close(variable)]
    return steps + diagnostic(240) + [close("a")]


def build(runtime: dict) -> dict:
    """Build and validate the near-boundary plan.

    Parameters
    ----------
    runtime : dict
        The runtime record of the environment.

    Returns
    -------
    dict
        The validated plan.
    """
    plan = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": (
            "delegated A11 near-boundary preparation; no live traffic authorised"
        ),
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": runtime,
        "endpoints": {
            "control": {"host": "127.0.0.1", "port": CONTROL_PORT},
            "data": {"host": "127.0.0.1", "port": DATA_PORT},
        },
        "expectation": {
            "case": "near-boundary",
            "fixture_name_hex": NAME.hex(),
            "global_download_limit": 8,
            "per_client_download_limit": 8,
            "per_ip_limit": PER_IP_LIMIT,
            "maximum_references": MAX_REFERENCES,
            "maximum_data_sockets": MAX_DATA_SOCKETS,
            "predicted_field101_bytes": 995,
            "a7_required_preflight_commit": "66b406a3db343467491e9446634c1b9bf8475fcc",
        },
        "steps": near(),
    }
    validate_plan(plan)
    return plan


def write_plans(*, runtime_record: str, output: str) -> None:
    """Write the near-boundary plan to a new output file and print its path.

    An existing output is refused before the runtime record is read.

    Parameters
    ----------
    runtime_record : str
        The JSON runtime record of the environment.
    output : str
        The output file, which must not exist yet.

    Raises
    ------
    SystemExit
        If the output already exists.
    """
    destination = Path(output)
    if destination.exists():
        message = f"Refusing existing output: {destination}"
        raise SystemExit(message)
    runtime = json.loads(Path(runtime_record).read_text(encoding="utf-8"))
    plan = build(runtime)
    destination.parent.mkdir(parents=True, exist_ok=True)
    destination.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"{destination}\n")


def main() -> None:
    """Write the near-boundary plan from the command line."""
    run(write_plans, __doc__)


if __name__ == "__main__":
    main()
