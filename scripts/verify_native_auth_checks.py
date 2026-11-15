"""Check the lookup and login-state captures of the native authentication corpus."""

import dataclasses as dc
import typing as typ

from native_auth_steps import KEY32
from native_banner_cases import URL
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_AGREEMENT_BYPASS,
    FIELD_BANNER_LINK,
    FIELD_BANNER_TYPE,
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_UNNAMED_WORD,
    FIELD_USER_ID,
    FIELD_VERSION,
    TYPE_BANNER_METADATA,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_USER_LEFT,
)
from verify_native_auth_frames import ADMIN, BYPASS, reply, roster, selected
from verify_native_banners import fields
from verify_native_core import (
    FIXTURE_UNNAMED_WORD_REPLY,
    FIXTURE_VERSION_REPLY,
    require,
)

type Report = dict[str, typ.Any]

KEY_LIMIT = 32  # a login key of this many bytes or more cannot be read
UNKNOWN_TRANSACTION = b"Unknown transaction type!"
BANNER_TYPE = b"GIFf"
# Each tuple is (type, is_reply, error) for one received frame.
ACK = (0, 1, 0)
FAILURE = (0, 1, 1)
PRIVILEGES = (TYPE_PRIVILEGES_NOTIFICATION, 0, 0)
AGREEMENT = (TYPE_LOGIN_AGREEMENT, 0, 0)
BANNER = (TYPE_BANNER_METADATA, 0, 0)
LOGIN_SHAPE = [ACK, PRIVILEGES, AGREEMENT]
DELAYED_LOGIN_SHAPE = [ACK, AGREEMENT, ACK, PRIVILEGES, BANNER, ACK]
AFTER_LOGIN_SHAPE = [FAILURE, FAILURE, ACK]  # the two replays, then an empty ACK
REAUTHENTICATION_SHAPE = [ACK, AGREEMENT, ACK, PRIVILEGES, AGREEMENT]
EARLY_REPLY_IDS = [1, 3, 4, 91]
DELAYED_REPLY_IDS = [1, 2, 90, 3, 4, 91]
REPLAY_IDS = [3, 4]
BASELINE_ROSTER = 10  # the observer's first roster request
VISIBLE_ROSTER = 13  # the roster that follows the subject's login
ROSTER_IDS = [10, 11, 12, 13, 14]
REAUTHENTICATION_ROSTER_IDS = [10, 11, 12, 13]
BOTH_VISIBLE = 2  # the observer and the subject
LOGIN_EXTRAS = {
    FIELD_VERSION: FIXTURE_VERSION_REPLY,
    FIELD_UNNAMED_WORD: FIXTURE_UNNAMED_WORD_REPLY,
}


@dc.dataclass(frozen=True, slots=True)
class Observation:
    """What the subject and the observer received in one state case.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The capture report.
    subject : list[dict[str, typing.Any]]
        The frames of the subject connection.
    views : dict[int, list[dict[str, typing.Any]]]
        The roster that each observer request returned, by request ID.
    updates : list[dict[str, typing.Any]]
        The presence updates that the observer received.
    departures : list[dict[str, typing.Any]]
        The departures that the observer received.
    """

    report: Report
    subject: list[Report]
    views: dict[int, list[Report]]
    updates: list[Report]
    departures: list[Report]


def requested_key(expected: Report) -> bytes:
    """Return the login key that the case sent.

    Returns
    -------
    bytes
        The key, empty when the case sent none.
    """
    if expected["key_hex"] is not None:
        return bytes.fromhex(expected["key_hex"])
    return b""


def check_lookup_success(report: Report, expected: Report, agreement: bytes) -> None:
    """Check a login that was accepted: its replies, privileges and agreement."""
    frames = report["frames"]
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in frames] == LOGIN_SHAPE,
        "Lookup success sequence differs",
    )
    require(fields(frames[0]) == LOGIN_EXTRAS, "Lookup login extras differ")
    key = requested_key(expected)
    require(
        fields(frames[1])
        == {FIELD_ACCESS_BITMAP: ADMIN if key.lower() == b"admin" else bytes(8)},
        "Lookup effective privileges differ",
    )
    require(fields(frames[2]) == {FIELD_DATA: agreement}, "Lookup agreement differs")


def check_lookup_failure(report: Report, expected: Report) -> None:
    """Check a login that was refused, with its fallback or file-name text."""
    frames = report["frames"]
    key = requested_key(expected)
    text = (
        (
            b"Cannot read account \xd2"
            + KEY32
            + b"\xd3:\rA bad file or folder name was specified.\rID 4/119 [-37]"
        )
        if len(key) >= KEY_LIMIT
        else b"Incorrect login."
    )
    require(
        len(frames) == 1
        and frames[0]["error"] == 1
        and frames[0]["is_reply"] == 1
        and fields(frames[0]) == {FIELD_ERROR_TEXT: text},
        "Lookup failure/fallback differs",
    )


def check_lookup(report: Report, expected: Report, agreement: bytes) -> None:
    """Check one login-key lookup, whether it succeeded or failed."""
    if expected["success"]:
        check_lookup_success(report, expected, agreement)
    else:
        check_lookup_failure(report, expected)


def observe(report: Report) -> Observation:
    """Collect the subject frames and the observer's views, checking the observer.

    Returns
    -------
    Observation
        What the two connections received.
    """
    subject = selected(report, "subject")
    observer = selected(report, "observer")
    views = {
        f["id"]: roster(f)
        for f in observer
        if f["is_reply"] and f["id"] >= BASELINE_ROSTER
    }
    require(
        all(f["error"] == 0 for f in observer if f["is_reply"]),
        "Observer request failed",
    )
    require(len(views[BASELINE_ROSTER]) == 1, "Observer baseline visibility differs")
    observer_uid = views[BASELINE_ROSTER][0]["uid"]
    require(
        all(
            any(r["uid"] == observer_uid for r in records) for records in views.values()
        ),
        "Observer disappeared from roster",
    )
    updates = [f for f in observer if f["type"] == TYPE_PRESENCE_UPDATE]
    departures = [f for f in observer if f["type"] == TYPE_USER_LEFT]
    return Observation(report, subject, views, updates, departures)


def check_login_sequence(observation: Observation, *, early: bool) -> None:
    """Check the order, the reply IDs and the login extras of the subject."""
    shape = [*(LOGIN_SHAPE if early else DELAYED_LOGIN_SHAPE), *AFTER_LOGIN_SHAPE]
    subject = observation.subject
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in subject] == shape,
        "Login state sequence differs",
    )
    require(
        [f["id"] for f in subject if f["is_reply"]]
        == (EARLY_REPLY_IDS if early else DELAYED_REPLY_IDS),
        "Login state reply correlation differs",
    )
    require(
        fields(reply(observation.report, 1, "subject")) == LOGIN_EXTRAS,
        "State login extras differ",
    )


def check_login_contents(
    observation: Observation, expected: Report, agreement: bytes | None
) -> None:
    """Check the agreement, privileges, banner and replays of the subject."""
    subject = observation.subject
    notice = next(f for f in subject if f["type"] == TYPE_LOGIN_AGREEMENT)
    if expected["bypass"]:
        notice_fields = {FIELD_AGREEMENT_BYPASS: b"\0\1"}
    else:
        notice_fields = {} if agreement is None else {FIELD_DATA: agreement}
    require(fields(notice) == notice_fields, "Agreement bypass contents differ")
    access = next(f for f in subject if f["type"] == TYPE_PRIVILEGES_NOTIFICATION)
    require(
        fields(access)
        == {FIELD_ACCESS_BITMAP: BYPASS if expected["bypass"] else ADMIN},
        "State privilege bitmap differs",
    )
    if not expected["early"]:
        banner = next(f for f in subject if f["type"] == TYPE_BANNER_METADATA)
        require(
            fields(banner) == {FIELD_BANNER_TYPE: BANNER_TYPE, FIELD_BANNER_LINK: URL},
            "Delayed banner differs",
        )
    for identifier in REPLAY_IDS:
        require(
            fields(reply(observation.report, identifier, "subject"))
            == {FIELD_ERROR_TEXT: UNKNOWN_TRANSACTION},
            "Online replay outcome differs",
        )


def check_login_visibility(observation: Observation, expected: Report) -> None:
    """Check what the observer saw of the subject across its login and close."""
    views = observation.views
    early = expected["early"]
    require(
        [len(views[i]) for i in ROSTER_IDS]
        == [1, 1, BOTH_VISIBLE if early else 1, BOTH_VISIBLE, 1],
        "Login visibility transition differs",
    )
    updates, departures = observation.updates, observation.departures
    require(
        len(updates) == len(departures) == 1,
        "Login observer notification count differs",
    )
    uid = int.from_bytes(fields(updates[0])[FIELD_USER_ID], "big")
    record = next(r for r in views[VISIBLE_ROSTER] if r["uid"] == uid)
    require(
        record["icon"] == expected["icon"]
        and record["name_hex"]
        == (b"auth-visible" if early else b"auth-completed").hex(),
        "Visible identity differs",
    )
    require(
        int.from_bytes(fields(departures[0])[FIELD_USER_ID], "big") == uid,
        "Departure UID differs",
    )


def check_reauthentication(observation: Observation) -> None:
    """Check a repeated login that was made before the acceptance."""
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in observation.subject]
        == REAUTHENTICATION_SHAPE,
        "Waiting-state repeated login differs",
    )
    require(
        [len(observation.views[i]) for i in REAUTHENTICATION_ROSTER_IDS]
        == [1, 1, BOTH_VISIBLE, BOTH_VISIBLE],
        "Repeated-login post-close snapshot differs",
    )
    require(
        len(observation.updates) == 1 and not observation.departures,
        "Repeated-login app-read notifications differ",
    )


def check_failed_session(observation: Observation) -> None:
    """Check a session that never became visible and was dropped."""
    subject, views = observation.subject, observation.views
    require(
        len(subject) == 1 and subject[0]["error"] == 1,
        "Preauth failure/retry silence differs",
    )
    require(
        all(len(v) == 1 for v in views.values()) and not observation.updates,
        "Failed session became visible",
    )
    require(len(observation.departures) == 1, "Missing unlisted-session departure")
    uid = int.from_bytes(fields(observation.departures[0])[FIELD_USER_ID], "big")
    require(
        all(uid not in {r["uid"] for r in v} for v in views.values()),
        "Failed session UID appeared in roster",
    )


def check_state(
    name: str, report: Report, expected: Report, agreement: bytes | None
) -> Report:
    """Check one login-state, reauthentication or failed-acceptance capture.

    Returns
    -------
    dict[str, typing.Any]
        The case name, the roster views and the notification counts.
    """
    observation = observe(report)
    if expected["kind"] == "login-state":
        check_login_sequence(observation, early=expected["early"])
        check_login_contents(observation, expected, agreement)
        check_login_visibility(observation, expected)
    elif expected["kind"] == "reauthentication" and not expected["preauth_acceptance"]:
        check_reauthentication(observation)
    else:
        check_failed_session(observation)
    return {
        "case": name,
        "rosters": observation.views,
        "observer_updates": len(observation.updates),
        "read_departures": len(observation.departures),
    }
