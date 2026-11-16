"""Check the agreement overflow observations and the native agreement file.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import dataclasses as dc
import json
import typing as typ

from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_AGREEMENT_BYPASS,
    FIELD_ERROR_TEXT,
    FIELD_UNNAMED_WORD,
    FIELD_USER_ID,
    FIELD_VERSION,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_USER_LEFT,
)
from verify_native_auth import ADMIN, BYPASS, reply, roster, selected
from verify_native_banners import fields
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Views = dict[int, list[Report]]

ACK = 0  # the type of a reply that carries no data of its own
REPORTED_VERSION = b"\0\xbe"
UNNAMED_WORD = b"\0\0"
BYPASS_FLAG = b"\0\1"
OBSERVER_FIRST_VIEW = 10  # the roster reads of the observer are numbered from here
EARLY_VIEWS = {10: 1, 12: 2, 13: 2, 14: 1}
DELAYED_VIEWS = {10: 1, 12: 1, 13: 1}
ONLINE_REQUEST_ID = 91
REPLAYED_IDS = [2, 3]
RECHECKED_VIEWS = [12, 13]
UNKNOWN_TYPE_TEXT = b"Unknown transaction type!"
VISIBLE_NAME = b"auth-visible"
VISIBLE_ICON = 1
AGREEMENT_PATH = "/Hotline19/Agreement.txt"


@dc.dataclass(frozen=True, slots=True)
class Overflow:
    """The subject's and the observer's frames of one overflow case."""

    report: Report
    subject: list[Report]
    observer: list[Report]
    early: bool
    views: Views
    updates: list[Report]
    departures: list[Report]


def check_subject(subject: list[Report], *, early: bool) -> None:
    """Check the subject's partial login: its frame shape and its ACK."""
    shape = [(ACK, 1, 0)]
    if early:
        shape += [
            (TYPE_PRIVILEGES_NOTIFICATION, 0, 0),
            (ACK, 1, 0),
            (ACK, 1, 1),
            (ACK, 1, 1),
        ]
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in subject] == shape,
        "Field-overflow partial login sequence differs",
    )
    require(
        fields(subject[0])
        == {FIELD_VERSION: REPORTED_VERSION, FIELD_UNNAMED_WORD: UNNAMED_WORD},
        "Overflow login ACK differs",
    )


def observe(report: Report, subject: list[Report], *, early: bool) -> Overflow:
    """Check the observer's account and views, and gather what it saw.

    Returns
    -------
    Overflow
        The frames, the roster views and the notifications.
    """
    observer = selected(report, "observer")
    require(
        fields(observer[1]) == {FIELD_ACCESS_BITMAP: BYPASS}
        and fields(observer[2]) == {FIELD_AGREEMENT_BYPASS: BYPASS_FLAG},
        "Overflow observer must use the independent bypass account",
    )
    views = {
        f["id"]: roster(f)
        for f in observer
        if f["is_reply"] and f["id"] >= OBSERVER_FIRST_VIEW
    }
    require(
        {k: len(v) for k, v in views.items()}
        == (EARLY_VIEWS if early else DELAYED_VIEWS),
        "Overflow visibility differs",
    )
    updates = [f for f in observer if f["type"] == TYPE_PRESENCE_UPDATE]
    departures = [f for f in observer if f["type"] == TYPE_USER_LEFT]
    require(
        len(updates) == int(early) and len(departures) == 1,
        "Overflow notifications differ",
    )
    return Overflow(report, subject, observer, early, views, updates, departures)


def check_early(overflow: Overflow, uid: int) -> None:
    """Check an early overflow: the subject is admitted and visible."""
    report, subject = overflow.report, overflow.subject
    require(
        fields(subject[1]) == {FIELD_ACCESS_BITMAP: ADMIN},
        "Overflow early privileges differ",
    )
    require(
        fields(reply(report, ONLINE_REQUEST_ID, "subject")) == {},
        "Overflow online request500 failed",
    )
    for identifier in REPLAYED_IDS:
        require(
            fields(reply(report, identifier, "subject"))
            == {FIELD_ERROR_TEXT: UNKNOWN_TYPE_TEXT},
            "Overflow online replay differs",
        )
    require(
        int.from_bytes(fields(overflow.updates[0])[FIELD_USER_ID], "big") == uid,
        "Overflow UID changed",
    )
    for identifier in RECHECKED_VIEWS:
        require(
            any(
                r["uid"] == uid
                and r["icon"] == VISIBLE_ICON
                and r["name_hex"] == VISIBLE_NAME.hex()
                for r in overflow.views[identifier]
            ),
            "Overflow identity differs",
        )


def check_delayed(overflow: Overflow, uid: int) -> None:
    """Check a delayed overflow: the subject never became visible."""
    require(
        all(uid not in {r["uid"] for r in view} for view in overflow.views.values()),
        "Delayed overflow became roster-visible",
    )
    require(
        any(
            e["event"] == "eof" and e["connection"] == "subject"
            for e in overflow.report["events"]
        ),
        "Delayed overflow trigger did not reach EOF",
    )


def check_overflow(report: Report, expected: Report) -> Report:
    """Check one agreement-field overflow case.

    Returns
    -------
    dict[str, typing.Any]
        The early flag, the roster views and the notification counts.
    """
    subject = selected(report, "subject")
    early = expected["early"]
    check_subject(subject, early=early)
    overflow = observe(report, subject, early=early)
    uid = int.from_bytes(fields(overflow.departures[0])[FIELD_USER_ID], "big")
    if early:
        check_early(overflow, uid)
    else:
        check_delayed(overflow, uid)
    return {
        "early": early,
        "rosters": overflow.views,
        "observer_updates": len(overflow.updates),
        "read_departures": len(overflow.departures),
    }


def native_file(root: Path, expected_type: bytes, expected_data: bytes) -> None:
    """Check the native agreement file's fork, bytes and Finder type."""
    extraction = json.loads((root / "extraction.json").read_text())
    matches = [r for r in extraction["records"] if r["path"] == AGREEMENT_PATH]
    require(len(matches) == 1, "Missing/duplicate positive native agreement path")
    record = matches[0]
    require(not record["directory"], "Expected agreement file, found directory")
    require(record["attributes"]["data"]["exit_code"] == 0, "Native fork read failed")
    require(
        (root / (record["key"] + ".data")).read_bytes() == expected_data,
        "Native agreement bytes differ",
    )
    stat = (root / (record["key"] + ".stat.txt")).read_text()
    require(
        "file type:\t" + expected_type.hex() + "  " in stat.lower(),
        "Native Finder type differs",
    )
