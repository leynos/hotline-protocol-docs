#!/usr/bin/env python3
"""Verify bounded native framing observations without generalizing duplicates."""

import dataclasses as dc
import hashlib
import json
import typing as typ
from pathlib import Path

from capture_acceptance import driver_in
from native_framing_cases import framing
from native_packet_evidence import reconcile
from native_plan import QUIET_WINDOW_SECONDS
from native_wire_names import (
    FIELD_ICON,
    FIELD_NAME,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from pcap_tcp import read_packets
from protocol_capture import verify_capture
from script_cli import run
from verify_native_core import require

type Report = dict[str, typ.Any]

# The login bootstrap of every case: the ACK, then the 354 and 109 notices.
BOOTSTRAP = [
    (0, 1, 0),
    (TYPE_PRIVILEGES_NOTIFICATION, 0, 0),
    (TYPE_LOGIN_AGREEMENT, 0, 0),
]
BOOTSTRAP_FRAMES = 3
NANOSECONDS_PER_SECOND = 1e9
ACK_PAYLOAD_HEX = "0000"
WIDE_ICON_LIMIT = 65535  # an icon above this travels as four bytes, not two
WIDE_ICON_BYTES = 4
NARROW_ICON_BYTES = 2
INITIAL_CASE = "initial-hypotheses/tlv-icon-ffffffff"
SCOPE = (
    "62 native cases; duplicate choices are observations, not a universal "
    "last-wins rule; silence is bounded to plan windows"
)


def check_quiet(report: Report, plan: Report) -> None:
    """Require measured silence before later input, not just an action label."""
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "expect_quiet":
            continue
        require(step["timeout"] >= QUIET_WINDOW_SECONDS, "Quiet observation too short")
        quiet = [
            e
            for e in report["events"]
            if e["action"] == action and e["event"] == "quiet"
        ]
        require(len(quiet) == 1, "Missing quiet event")
        previous = [e for e in report["events"] if e["action"] < action]
        require(
            quiet[0]["elapsed_ns"] - previous[-1]["elapsed_ns"]
            >= step["timeout"] * NANOSECONDS_PER_SECOND,
            "Quiet observation was shorter than its plan",
        )


def check_acks(remaining: list[Report], expected: Report) -> Report:
    """Check that each remaining frame is the empty ACK of the planned ID.

    Returns
    -------
    dict[str, typing.Any]
        No observations to report.
    """
    kind = expected["kind"]
    ids = expected["ids"] if kind == "ack-sequence" else [expected["id"]]
    require(len(remaining) == len(ids), "ACK count changed")
    for frame, identifier in zip(remaining, ids, strict=True):
        require(
            (
                frame["type"],
                frame["is_reply"],
                frame["id"],
                frame["error"],
                frame["payload_hex"],
            )
            == (0, 1, identifier, 0, ACK_PAYLOAD_HEX),
            "ACK bytes changed",
        )
    return {}


def check_close(report: Report, remaining: list[Report], packets: Report) -> Report:
    """Check that the server closed the socket without any numbered reply.

    Returns
    -------
    dict[str, typing.Any]
        No observations to report.
    """
    require(not remaining, "Unexpected numbered reply before close")
    require(any(e["event"] == "eof" for e in report["events"]), "Missing socket EOF")
    require(packets["guest_server_initiated_close"], "Guest did not initiate close")
    return {}


def check_settings(remaining: list[Report], expected: Report) -> Report:
    """Check the one 301 notification that a settings request provokes.

    Returns
    -------
    dict[str, typing.Any]
        The effective name and the emitted icon, in hexadecimal.
    """
    require(len(remaining) == 1, "Settings notification count changed")
    frame = remaining[0]
    require(
        (frame["type"], frame["is_reply"], frame["error"])
        == (TYPE_PRESENCE_UPDATE, 0, 0),
        "Settings notification envelope changed",
    )
    fields = {f["id"]: f["hex"] for f in frame["fields"]}
    require(fields[FIELD_NAME] == expected["name_hex"], "Effective name differs")
    icon = int.from_bytes(bytes.fromhex(fields[FIELD_ICON]), "big")
    if expected["kind"] == "duplicate-settings":
        require(icon in expected["allowed_icons"], "Unexpected duplicate selection")
    else:
        require(icon == expected["icon"], "Effective icon differs")
    require(
        len(bytes.fromhex(fields[FIELD_ICON]))
        == (WIDE_ICON_BYTES if icon > WIDE_ICON_LIMIT else NARROW_ICON_BYTES),
        "Icon wire width differs",
    )
    return {
        "effective_name_hex": fields[FIELD_NAME],
        "emitted_icon_hex": fields[FIELD_ICON],
    }


def check_outcome(report: Report, expected: Report, packets: Report) -> Report:
    """Check handler-visible outcomes after the three-frame login bootstrap.

    Returns
    -------
    dict[str, typing.Any]
        The observations that the case reports.

    Raises
    ------
    ValueError
        If the expectation names a kind that is not known.
    """
    frames = report["frames"]
    require(len(frames) >= BOOTSTRAP_FRAMES, "Missing login bootstrap")
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in frames[:BOOTSTRAP_FRAMES]]
        == BOOTSTRAP,
        "Login bootstrap changed",
    )
    remaining = frames[BOOTSTRAP_FRAMES:]
    kind = expected["kind"]
    if kind in {"ack", "ack-sequence"}:
        return check_acks(remaining, expected)
    if kind == "close":
        return check_close(report, remaining, packets)
    if kind in {"settings", "duplicate-settings"}:
        return check_settings(remaining, expected)
    message = "Unknown semantic expectation"
    raise ValueError(message)


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What a framing corpus holds besides its cases.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    host : list[dict[str, typ.Any]]
        The host packet capture.
    guest : list[dict[str, typ.Any]]
        The guest packet capture.
    sources : set[str]
        The hashes of the retained capture drivers.
    """

    directory: Path
    host: list[dict[str, typ.Any]]
    guest: list[dict[str, typ.Any]]
    sources: set[str]


def verify_case(
    corpus: Corpus, name: str, planned: tuple[list[Report], Report]
) -> Report:
    """Verify one captured case of a framing corpus.

    Returns
    -------
    dict[str, typing.Any]
        The case name, its packet observations and its outcome.
    """
    steps, expected = planned
    case = corpus.directory / "transcripts" / name
    plan = json.loads((case / "plan.json").read_text())
    report = verify_capture(case)
    require(report["status"] == "completed", name + ": capture failed")
    require(driver_in(report, corpus.sources), "Missing capture-driver source")
    require(plan["steps"] == steps and plan["expectation"] == expected, "Plan differs")
    packets = reconcile(report, corpus.host, corpus.guest)["main"]
    check_quiet(report, plan)
    return {"case": name, **packets, **check_outcome(report, expected, packets)}


def verify(directory: Path) -> Report:
    """Check the complete declared matrix against both packet capture views.

    Returns
    -------
    dict[str, typing.Any]
        The observations of each case and the scope they support.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected_cases = framing()
    names = {p.name for p in (directory / "transcripts").iterdir() if p.is_dir()}
    require(names == set(expected_cases), "Framing corpus inventory differs")
    sources = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    corpus = Corpus(directory, host, guest, sources)
    observations = [
        verify_case(corpus, name, planned)
        for name, planned in sorted(expected_cases.items())
    ]
    initial = verify_capture(directory / INITIAL_CASE)
    require(initial["status"] == "completed", "Initial icon capture status differs")
    require(
        next(f for f in initial["frames"][-1]["fields"] if f["id"] == FIELD_ICON)["hex"]
        == "ffffffff",
        "Initial disproven icon hypothesis changed",
    )
    reconcile(initial, host, guest)
    return {"cases": observations, "initial_hypotheses": 1, "scope": SCOPE}


def show(directory: str) -> None:
    """Print the verification of the corpus in ``directory``."""
    print(json.dumps(verify(Path(directory)), indent=2))


def main() -> None:
    """Verify a framing corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
