#!/usr/bin/env python3
"""Verify controlled native queue positions, ownership, modes and expiry."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from native_packet_evidence import reconcile
from native_queue_cases import Case, queues, timer
from native_wire_names import (
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    TYPE_PRESENCE_UPDATE,
    TYPE_USER_LEFT,
)
from pcap_tcp import read_packets
from protocol_capture import decode_frame, verify_capture
from script_cli import run
from verify_native_core import require
from verify_native_framing import check_quiet
from verify_native_queue_expectations import (
    CASE_CHECKS,
    Capture,
    check_inventory,
    check_positions,
)
from verify_native_queue_support import frame_time, notices, references

type Report = dict[str, typ.Any]

# frame_time is imported from this module by verify_native_cleanup,
# native_folder_clock_checks and verify_native_banner_formats, and notices and
# references by test_native_queues; the names stay importable from here.
__all__ = ["check_case", "frame_time", "main", "notices", "references", "verify"]

# transfer-contracts.md, "Queue": the fixture admits two transfers at once and
# one for each client session.
GLOBAL_MAX_DOWNLOADS = 2
PER_CLIENT_MAX_DOWNLOADS = 1
OWNERS = {"a", "b"}
UNREAD_CONTROL_TYPES = {TYPE_PRESENCE_UPDATE, TYPE_USER_LEFT}
SCOPE = (
    "Controlled two-global/one-per-session queues, finite ordering and bounded "
    "timeout observations; no universal FIFO or starvation guarantee"
)


def check_case(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    name: str,
    report: Report,
    plan: Report,
    packets: dict[str, typ.Any],
    guest: list[dict[str, typ.Any]],
) -> dict[str, typ.Any]:
    """Check one queue case and report the positions it promised.

    Returns
    -------
    dict[str, typing.Any]
        The initial positions, the notification positions and any timing.

    Raises
    ------
    ValueError
        If ``name`` is not a known queue case.
    """
    refs = references(report, plan)
    capture = Capture(report, plan, packets, guest, refs, notices(report, refs))
    if name not in CASE_CHECKS:
        message = "Unknown queue case"
        raise ValueError(message)
    expected = CASE_CHECKS[name](capture)
    check_positions(capture, expected)
    check_inventory(report, plan)
    return {
        "initial_positions": expected.initial,
        "notification_positions": expected.notes,
        **expected.timing,
    }


def check_unread(suffix: bytes) -> None:
    """Check that the unread tail of a control connection holds only 301 and 302."""
    while suffix:
        require(len(suffix) >= FRAME_HEADER_BYTES, "Short unread notification")
        size = FRAME_HEADER_BYTES + int.from_bytes(
            suffix[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big"
        )
        require(size <= len(suffix), "Truncated unread notification")
        frame = decode_frame(suffix[:size])
        require(
            frame["type"] in UNREAD_CONTROL_TYPES
            and frame["is_reply"] == 0
            and frame["error"] == 0,
            "Unexpected unread control message",
        )
        suffix = suffix[size:]


def check_plan(plan: Report, expected_case: Case) -> None:
    """Check that a capture completed from the plan that the planner emits."""
    steps, expectation = expected_case
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Queue plan differs",
    )
    config = plan["environment"]["queue_test_configuration"]
    require(
        config["global_max_downloads"] == GLOBAL_MAX_DOWNLOADS
        and config["per_client_max_downloads"] == PER_CLIENT_MAX_DOWNLOADS,
        "Queue fixture configuration differs",
    )


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What a queue corpus holds besides its cases.

    Attributes
    ----------
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    source_hashes : set[str]
        The hashes of the retained capture drivers.
    unread : dict[str, dict[str, str]]
        The retained unread tail of each owner, by case.
    """

    host: list[dict[str, typ.Any]]
    guest: list[dict[str, typ.Any]]
    source_hashes: set[str]
    unread: dict[str, dict[str, str]]


def verify_case(
    directory: Path, name: str, expected_case: Case, corpus: Corpus
) -> dict[str, typ.Any]:
    """Verify one captured case of a queue corpus.

    Returns
    -------
    dict[str, typing.Any]
        The case name, its connections and its checked positions.
    """
    case = directory / "transcripts" / name
    report = verify_capture(case)
    plan = json.loads((case / "plan.json").read_text())
    require(report["status"] == "completed", "Queue capture failed")
    require(
        report["driver_sha256"] in corpus.source_hashes,
        "Missing queue capture source",
    )
    check_plan(plan, expected_case)
    suffixes = {
        owner: bytes.fromhex(value)
        for owner, value in corpus.unread.get(name, {}).items()
    }
    for owner, suffix in suffixes.items():
        require(owner in OWNERS, "Unread transfer data is not permitted")
        check_unread(suffix)
    packets = reconcile(report, corpus.host, corpus.guest, suffixes)
    check_quiet(report, plan)
    return {
        "case": name,
        "connections": packets,
        **check_case(name, report, plan, packets, corpus.guest),
    }


def verify(directory: Path) -> dict[str, typ.Any]:
    """Verify every case of a retained queue corpus.

    Returns
    -------
    dict[str, typing.Any]
        The observations of each case, and the scope they support.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = queues() | timer()
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Queue corpus inventory differs",
    )
    corpus = Corpus(
        host,
        guest,
        {
            hashlib.sha256(p.read_bytes()).hexdigest()
            for p in (directory / "sources").glob("protocol_capture*.txt")
        },
        json.loads((directory / "unread-output.json").read_text()),
    )
    observations = [
        verify_case(directory, name, case, corpus) for name, case in expected.items()
    ]
    return {"cases": observations, "scope": SCOPE}


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a queue corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
