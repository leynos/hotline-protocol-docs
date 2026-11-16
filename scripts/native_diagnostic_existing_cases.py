#!/usr/bin/env python3
"""Generate bounded read-only 303 load plans for the verified existing fixture."""

import json
import sys
from pathlib import Path

from native_diagnostic_cases import diagnostic_request
from native_plan import close, packet, payload, read, send
from native_queue_cases import attach, cancel, session
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    TYPE_DOWNLOAD_FILE,
    TYPE_ENUMERATE_ACCOUNTS,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
)
from protocol_capture import ORACLE_SHA256, validate_plan
from script_cli import UsageError, run

NAME = b"mothra-race-fixture"
MAX_REFERENCES = 16
MAX_DATA_SOCKETS = 8
CONTROL_PORT = 15500
DATA_PORT = 15501
PER_IP_LIMIT = 5
DENSITY_ACTIVE_PROBE = 3  # the fourth active reference carries the first probe
# Queued index -> identifier of the 303 probe sent after that queued reference.
DENSITY_QUEUED_PROBES = {3: 60, 7: 61}


def exchange(kind: int, identifier: int, fields: list[tuple[int, bytes]]) -> list[dict]:
    """Plan one request on connection ``a`` and its reply.

    Parameters
    ----------
    kind : int
        The transaction type of the request.
    identifier : int
        The transaction identifier of the request.
    fields : list[tuple[int, bytes]]
        The field identifiers and values of the request.

    Returns
    -------
    list[dict]
        The send step and the matching read step.
    """
    return [
        send(packet(kind, identifier, payload(fields)), "a"),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def roster(identifier: int) -> list[dict]:
    """Plan a roster request that saves the administrator's UID.

    Parameters
    ----------
    identifier : int
        The transaction identifier of the request.

    Returns
    -------
    list[dict]
        The send step and the read step that saves ``admin_uid``.
    """
    return [
        send(packet(TYPE_GET_USER_ROSTER, identifier), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save={"name": "admin_uid", "offset": 26, "size": 2},
        ),
    ]


def diagnostic(identifier: int, uid: str | bytes = "admin_uid") -> list[dict]:
    """Plan one diagnostic request and its reply on connection ``a``.

    Parameters
    ----------
    identifier : int
        The transaction identifier of the request.
    uid : str | bytes
        The current-session UID name or the raw two-byte UID.

    Returns
    -------
    list[dict]
        The send step and the matching read step.
    """
    return [
        diagnostic_request("a", identifier, uid),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def request(identifier: int, variable: str) -> list[dict]:
    """Plan a download request for the fixture and save its reference.

    Parameters
    ----------
    identifier : int
        The transaction identifier of the request.
    variable : str
        The name under which the reference and its size are saved.

    Returns
    -------
    list[dict]
        The send step and the read step that saves the reference and size.
    """
    return [
        send(
            packet(TYPE_DOWNLOAD_FILE, identifier, payload([(FIELD_FILE_NAME, NAME)])),
            "a",
        ),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save_fields={
                variable: FIELD_TRANSFER_REFERENCE,
                variable + "_size": FIELD_TRANSFER_SIZE,
            },
        ),
    ]


def finish_active(variable: str, identifier: int) -> list[dict]:
    """Plan the cancellation of an active reference and the end of its socket.

    Parameters
    ----------
    variable : str
        The name of the saved reference of the active transfer.
    identifier : int
        The transaction identifier of the cancellation.

    Returns
    -------
    list[dict]
        The cancellation, the end-of-file read and the close step.
    """
    return [
        *cancel("a", identifier, variable),
        {"op": "read_eof", "connection": variable, "timeout": 30},
        close(variable),
    ]


def one_active_one_queued() -> list[dict]:
    """Plan the 2/1 limits, which require a same-session queued second reference.

    Returns
    -------
    list[dict]
        The steps of the case, in order.
    """
    steps = session("a") + roster(10)
    steps += request(11, "active") + attach("active")
    steps += request(12, "queued") + diagnostic(13)
    steps += diagnostic(14, b"\xff\xff")
    steps += cancel("a", 15, "queued") + finish_active("active", 16)
    return steps + diagnostic(17) + [close("a")]


def density() -> list[dict]:
    """Plan the 8/8 limits with fixed 4+0, 8+4 and 8+8 points, never expanding.

    Returns
    -------
    list[dict]
        The steps of the case, in order.
    """
    steps = session("a") + roster(10)
    for index in range(MAX_DATA_SOCKETS):
        variable = f"active{index}"
        steps += request(20 + index, variable) + attach(variable)
        if index == DENSITY_ACTIVE_PROBE:
            steps += diagnostic(35)
    for index in range(MAX_REFERENCES - MAX_DATA_SOCKETS):
        steps += request(40 + index, f"queued{index}")
        if index in DENSITY_QUEUED_PROBES:
            steps += diagnostic(DENSITY_QUEUED_PROBES[index])
    for index in reversed(range(MAX_REFERENCES - MAX_DATA_SOCKETS)):
        steps += cancel("a", 70 + index, f"queued{index}")
    for index in reversed(range(MAX_DATA_SOCKETS)):
        variable = f"active{index}"
        steps += [*cancel("a", 80 + index, variable), close(variable)]
    return steps + diagnostic(90) + [close("a")]


def postflight() -> list[dict]:
    """Plan the read-only baseline taken after General Options are restored.

    Returns
    -------
    list[dict]
        The steps of the case, in order.
    """
    steps = session("a")
    steps += exchange(TYPE_ENUMERATE_ACCOUNTS, 10, [])
    steps += exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
    steps += exchange(TYPE_GET_FILE_INFO, 12, [(FIELD_FILE_NAME, NAME)])
    return steps + roster(13) + diagnostic(14) + [close("a")]


CASES = {
    "one-active-one-queued": (one_active_one_queued, 2, 1),
    "density": (density, 8, 8),
    "postflight": (postflight, 100, 10),
}
CASE_LIST = ",".join(CASES)
DESCRIPTION = f"{__doc__}\nCases: {{{CASE_LIST}}}\n"


def build(case: str, runtime: dict) -> dict:
    """Build and validate the plan of one existing-fixture case.

    Parameters
    ----------
    case : str
        A key of ``CASES``.
    runtime : dict
        The runtime record of the environment.

    Returns
    -------
    dict
        The validated plan.
    """
    generator, global_limit, client_limit = CASES[case]
    steps = generator()
    plan = {
        "schema_version": 1,
        "profile": "native-mac-oracle",
        "operator": "delegated A8 existing-fixture diagnostic operator",
        "oracle_sha256": ORACLE_SHA256,
        "gap_ids": ["GAP-037"],
        "environment": runtime,
        "endpoints": {
            "control": {"host": "127.0.0.1", "port": CONTROL_PORT},
            "data": {"host": "127.0.0.1", "port": DATA_PORT},
        },
        "expectation": {
            "case": case,
            "fixture_name_hex": NAME.hex(),
            "global_download_limit": global_limit,
            "per_client_download_limit": client_limit,
            "per_ip_limit": PER_IP_LIMIT,
            "maximum_references": MAX_REFERENCES,
            "maximum_data_sockets": MAX_DATA_SOCKETS,
            "a7_required_preflight_commit": "66b406a3db343467491e9446634c1b9bf8475fcc",
        },
        "steps": steps,
    }
    validate_plan(plan)
    return plan


def write_case(case: str, *, runtime_record: str, output: str) -> None:
    """Write the plan of one case to a new output file and print its path.

    The runtime record is read first, then an existing output is refused, then
    the plan is built and written.

    Parameters
    ----------
    case : str
        The case to write, one of the keys of ``CASES``.
    runtime_record : str
        The JSON runtime record of the environment.
    output : str
        The output file, which must not exist yet.

    Raises
    ------
    UsageError
        If ``case`` is not one of the keys of ``CASES``.
    SystemExit
        If the output already exists.
    """
    if case not in CASES:
        choices = ", ".join(CASES)
        message = f"argument case: invalid choice: {case!r} (choose from {choices})"
        raise UsageError(message)
    runtime = json.loads(Path(runtime_record).read_text(encoding="utf-8"))
    destination = Path(output)
    if destination.exists():
        message = f"Refusing existing output: {destination}"
        raise SystemExit(message)
    destination.parent.mkdir(parents=True, exist_ok=True)
    plan = build(case, runtime)
    destination.write_text(json.dumps(plan, indent=2) + "\n", encoding="utf-8")
    sys.stdout.write(f"{destination}\n")


def main() -> None:
    """Write the requested existing-fixture case from the command line."""
    run(write_case, DESCRIPTION)


if __name__ == "__main__":
    main()
