#!/usr/bin/env python3
"""Verify native ID collision/reuse and request/reply envelope observations."""

import hashlib
import json
import typing as typ
from pathlib import Path

from capture_acceptance import driver_is
from native_correlation_cases import correlation
from native_packet_evidence import reconcile
from native_wire_names import (
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_NAME,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from script_cli import run
from verify_native_banners import fields
from verify_native_core import require
from verify_native_correlation_oracle import verify_oracle
from verify_native_framing import check_quiet

type Report = dict[str, typ.Any]

# The oracle checks live in verify_native_correlation_oracle; verify_oracle stays
# importable from this module. check_outcome, verify and verify_oracle are
# imported by test_native_correlation.
__all__ = ["check_outcome", "main", "verify", "verify_oracle"]

CASE_COUNT = 24
ACK_TYPE = 0  # a reply to a request that carries no data of its own
# The type, ID, reply flag and error of the first three frames of every case.
BOOTSTRAP = [
    (ACK_TYPE, 1, 1, 0),
    (TYPE_PRIVILEGES_NOTIFICATION, 1, 0, 0),
    (TYPE_LOGIN_AGREEMENT, 2, 0, 0),
]
NOTIFICATION_ID = 3  # the first notification ID that the server allocates
UNSUPPORTED_ERROR = 1
UNSUPPORTED_REPLIES = 2  # the error reply and the reply to the follow-up probe
UNSUPPORTED_TEXT = b"Unknown transaction type!"
UNSUPPORTED_REQUEST_ID = 10
UNSUPPORTED_FOLLOWUP_ID = 11
EMPTY_PAYLOAD_HEX = "0000"
NOTIFICATION_KINDS = {"notification", "collision-notification"}
NOTIFICATION_ORDER = [1, 0, 1]  # reply, notification, reply
COLLISION_ORDER = [0, 1]  # notification, reply
NS_PER_SECOND = 1e9


def check_close(report: Report, packets: Report, remaining: list[Report]) -> Report:
    """Check a case that ends with the server closing the connection.

    Returns
    -------
    dict[str, typing.Any]
        Whether the native close followed a half-close.
    """
    half_closed = any(e["event"] == "shutdown_write" for e in report["events"])
    require(
        not remaining and any(e["event"] == "eof" for e in report["events"]),
        "Missing unnumbered close",
    )
    require(
        (
            not packets["main"]["guest_server_initiated_close"]
            and packets["main"]["guest_server_close_kind"] == "FIN"
        )
        if half_closed
        else packets["main"]["guest_server_initiated_close"],
        "Missing native reply-size close",
    )
    return {"native_close_after_half_close": half_closed}


def check_unsupported(replies: list[Report], notifications: list[Report]) -> None:
    """Check the error reply to an unsupported request type."""
    require(
        len(replies) == UNSUPPORTED_REPLIES and not notifications,
        "Unsupported request outcomes differ",
    )
    error = replies[0]
    require(
        (error["type"], error["id"], error["is_reply"], error["error"])
        == (ACK_TYPE, UNSUPPORTED_REQUEST_ID, 1, UNSUPPORTED_ERROR),
        "Unsupported error envelope differs",
    )
    require(
        fields(error) == {FIELD_ERROR_TEXT: UNSUPPORTED_TEXT},
        "Unsupported error text differs",
    )


def check_replies(replies: list[Report], ids: list[int]) -> None:
    """Check that each direct reply is an empty ACK with the request's ID."""
    require(len(replies) == len(ids), "Direct reply count differs")
    for frame, identifier in zip(replies, ids, strict=True):
        require(
            (
                frame["type"],
                frame["id"],
                frame["is_reply"],
                frame["error"],
                frame["payload_hex"],
            )
            == (ACK_TYPE, identifier, 1, 0, EMPTY_PAYLOAD_HEX),
            "Direct reply correlation differs",
        )


def check_notification(
    expected: Report, notifications: list[Report], remaining: list[Report]
) -> None:
    """Check the one presence notification and its place among the replies."""
    require(len(notifications) == 1, "Notification count differs")
    frame = notifications[0]
    require(
        (frame["type"], frame["id"], frame["error"])
        == (TYPE_PRESENCE_UPDATE, NOTIFICATION_ID, 0),
        "Notification ID allocation differs",
    )
    values = fields(frame)
    require(
        values[FIELD_NAME].hex() == expected["name_hex"]
        and int.from_bytes(values[FIELD_ICON], "big") == expected["icon"],
        "Collision/notification settings differ",
    )
    require(
        [f["is_reply"] for f in remaining]
        == (
            NOTIFICATION_ORDER
            if expected["kind"] == "notification"
            else COLLISION_ORDER
        ),
        "Notification/reply ordering differs",
    )


def check_outcome(report: Report, expected: Report, packets: Report) -> Report:
    """Check the frames that one case received.

    Returns
    -------
    dict[str, typing.Any]
        The IDs of the direct replies and of the notifications.
    """
    frames = report["frames"]
    require(report["status"] == "completed", "Incomplete ID observation")
    require(
        [(f["type"], f["id"], f["is_reply"], f["error"]) for f in frames[:3]]
        == BOOTSTRAP,
        "ID bootstrap namespaces differ",
    )
    require(all(f["flags"] == 0 for f in frames), "Native emitted flags differ")
    remaining = frames[3:]
    replies = [f for f in remaining if f["is_reply"]]
    notifications = [f for f in remaining if not f["is_reply"]]
    if expected["kind"] == "close":
        return check_close(report, packets, remaining)
    if expected["kind"] == "unsupported":
        check_unsupported(replies, notifications)
        replies = replies[1:]
        ids = [UNSUPPORTED_FOLLOWUP_ID]
    else:
        ids = expected["ids"]
    check_replies(replies, ids)
    if expected["kind"] in NOTIFICATION_KINDS:
        check_notification(expected, notifications, remaining)
    else:
        require(not notifications, "Unexpected notification")
    return {
        "reply_ids": [f["id"] for f in replies],
        "notification_ids": [f["id"] for f in notifications],
    }


def check_pauses(report: Report, steps: list[Report]) -> None:
    """Check that each planned pause lasted at least as long as planned."""
    for action, step in enumerate(steps):
        if step["op"] == "pause":
            event = next(
                e
                for e in report["events"]
                if e["action"] == action and e["event"] == "pause"
            )
            before = max(
                e["elapsed_ns"] for e in report["events"] if e["action"] < action
            )
            require(
                event["elapsed_ns"] - before >= step["seconds"] * NS_PER_SECOND,
                "Shortened dispatch pause",
            )


def check_case(
    directory: Path, name: str, case: tuple[list[Report], Report], corpus: Report
) -> tuple[Report, Report]:
    """Check one recorded case against its plan, its capture and its packets.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The case's outcome and its packet reconciliation.
    """
    steps, expectation = case
    path = directory / "transcripts" / name
    plan = json.loads((path / "plan.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "ID preparation plan differs",
    )
    report = verify_capture(path)
    require(
        driver_is(report, corpus["source_hash"]),
        "Missing ID capture-driver source",
    )
    require(
        report["streams"]["main"]["sent_hex"]
        == "".join(s["hex"] for s in steps if s["op"] == "send"),
        "Physical ID input differs",
    )
    observation = reconcile(report, corpus["host"], corpus["guest"])
    check_quiet(report, plan)
    check_pauses(report, steps)
    return check_outcome(report, expectation, observation), observation


def verify(directory: Path) -> Report:
    """Verify the retained ID and envelope corpus.

    Returns
    -------
    dict[str, typing.Any]
        The outcome of every case and its packet reconciliation.
    """
    manifest = json.loads((directory / "manifest.json").read_text())
    cases = correlation()
    require(
        set(manifest["cases"]) == set(cases) and len(manifest["cases"]) == CASE_COUNT,
        "ID case inventory differs",
    )
    require(manifest["oracle_sha256"] == ORACLE_SHA256, "ID corpus identity differs")
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    source_hash = hashlib.sha256(
        (directory / "protocol_capture.py.as-run.txt").read_bytes()
    ).hexdigest()
    corpus = {"host": host, "guest": guest, "source_hash": source_hash}
    results, observations = {}, {}
    for name, case in cases.items():
        results[name], observations[name] = check_case(directory, name, case, corpus)
    require(
        observations
        == json.loads((directory / "packet-reconciliation.json").read_text()),
        "ID packet observations differ",
    )
    verify_oracle(directory)
    return {"cases": results, "packet_reconciliation": observations}


def show(directory: str) -> None:
    """Print the summary of the verification of the corpus in ``directory``."""
    result = verify(Path(directory))
    count = len(result["cases"])
    print(f"Verified {count} native ID/envelope cases and 25 oracle queries")


def main() -> None:
    """Verify a native ID and envelope corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
