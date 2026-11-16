"""Gate what each ban-expiry case must have observed on the wire.

Part of the ban-expiry controller (``native_ban_expiry_control``), which
re-exports every public name below. Each gate reads a finished case report and
fails closed with a ``ValueError`` that names what differed.
"""

import native_ban_expiry_cases as cases
from native_ban_expiry_cases import TEMPORARY_NOTICE as TEMP_TEXT
from native_ban_expiry_control_core import Report, require
from verify_native_auth import ADMIN, reply, roster
from verify_native_shx import fields

# The frames that a login must have produced before the kick is sent.
MIN_ADMIN_FRAMES = 5
MIN_TARGET_FRAMES = 3
# Wire values: the privilege bit of the kick, the roster size and the opcodes.
KICK_PRIVILEGE_BIT = 63 - 22
ROSTER_ROWS = 2
UID_BYTES = 2
GET_USER_ACCESS = 354
AGREEMENT = 109
USER_JOINED = 301
USER_LEFT = 302
DISCONNECT_MESSAGE = 104
ROSTER_REPLY_ID = 32
SERVER_NOTICE_FIELD = 100
KICK_REPLY_ID = 33
TARGET_QUIET_REPLY_ID = 80
CREATE_REPLY_ID = 31
LOOKUP_REPLY_ID = 30
READBACK_REPLY_ID = 32
PROBE_REPLY_ID = 1
PROBE_ROSTER_ID = 40
ACCEPTED_SENDS = 3
REFUSED_SENDS = 2
TRTP_HELLO = "54525450484f544c00010002"
ACCEPTING_PROBES = frozenset({"kick0-probe", "post-probe"})
UNPROTECTED_KICKS = frozenset({"kick0", "tempban"})


def field_map(frame: Report) -> dict[int, bytes]:
    """Read a frame's fields as a map, refusing a repeated field.

    Returns
    -------
    dict[int, bytes]
        The field values by identifier.
    """
    result = fields(frame)
    require(len(result) == len(frame["fields"]), "Duplicate frame field")
    return result


# The criteria that ``relevant`` accepts, each named for the frame key it tests.
FRAME_KEYS = {"kind": "type", "identifier": "id", "reply_marker": "is_reply"}


def relevant(report: Report, connection: str, **wanted: int) -> list[Report]:
    """Select the frames of one connection, narrowed by type, id or reply marker.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The case report.
    connection : str
        The connection label.
    **wanted : int
        Any of ``kind`` (the frame type), ``identifier`` (the transaction id)
        and ``reply_marker`` (``is_reply``); a frame must equal each one given.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching frames, in order.

    Raises
    ------
    TypeError
        If a criterion is not one of the three named.
    """
    unknown = sorted(set(wanted) - set(FRAME_KEYS))
    if unknown:
        message = f"unknown frame criteria: {', '.join(unknown)}"
        raise TypeError(message)
    return [
        f
        for f in report["frames"]
        if f["connection"] == connection
        and all(f[FRAME_KEYS[name]] == value for name, value in wanted.items())
    ]


def _logins(main: list[Report], target: list[Report], *, protected: bool) -> None:
    """Check the administrator and target logins that precede a kick."""
    require(
        len(main) >= MIN_ADMIN_FRAMES and len(target) >= MIN_TARGET_FRAMES,
        "Missing admin or target login",
    )
    require(
        main[0]["error"] == 0 and main[0]["is_reply"] == 1,
        "Administrator Login107 failed",
    )
    admin_access = field_map(main[1]).get(110, b"")
    require(
        main[1]["type"] == GET_USER_ACCESS
        and admin_access == ADMIN
        and bool(int.from_bytes(admin_access, "big") & (1 << KICK_PRIVILEGE_BIT)),
        "Administrator privilege22 absent",
    )
    expected_access = cases.PROTECTED_ACCESS if protected else cases.ZERO_ACCESS
    require(
        target[0]["error"] == 0
        and target[0]["is_reply"] == 1
        and target[1]["type"] == GET_USER_ACCESS
        and field_map(target[1]) == {110: expected_access}
        and target[2]["type"] == AGREEMENT,
        "Target 354/access/agreement differs",
    )


def _announced_target(main: list[Report], saved_uid: bytes, *, protected: bool) -> None:
    """Check that the saved user id and name are the target's own."""
    joins = [f for f in main if f["type"] == USER_JOINED and not f["is_reply"]]
    require(len(joins) == 1, "Target 301 absent or ambiguous")
    announced = field_map(joins[0])
    expected_name = cases.PROTECTED_NAME if protected else cases.ZERO_NAME
    require(
        announced.get(103) == saved_uid
        and announced.get(102) == expected_name
        and len(saved_uid) == UID_BYTES
        and int.from_bytes(saved_uid, "big") > 0,
        "Saved current target UID/name differs",
    )


def _roster_identity(main: list[Report], saved_uid: bytes, *, protected: bool) -> None:
    """Check the current roster holds the target and a distinct administrator."""
    snapshots = [f for f in main if f["is_reply"] and f["id"] == ROSTER_REPLY_ID]
    require(len(snapshots) == 1, "Current roster missing")
    rows = roster(snapshots[0])
    expected_name = cases.PROTECTED_NAME if protected else cases.ZERO_NAME
    uid = int.from_bytes(saved_uid, "big")
    require(
        len(rows) == ROSTER_ROWS
        and sum(r["uid"] == uid and r["name_hex"] == expected_name.hex() for r in rows)
        == 1,
        "Current roster target identity differs",
    )
    require(
        any(
            r["name_hex"] == b"framing-fixture".hex() and r["uid"] != uid for r in rows
        ),
        "Current admin and target roster identities overlap",
    )


def identity_before_110(
    frames: list[Report], saved_uid: bytes, *, protected: bool
) -> None:
    """Require both logins, the target's join and the roster before a kick.

    Parameters
    ----------
    frames : list[dict[str, typing.Any]]
        The frames decoded so far.
    saved_uid : bytes
        The target's user id as saved from its join.
    protected : bool
        Whether the target is the protected account.
    """
    report = {"frames": frames}
    main = relevant(report, "main")
    target = relevant(report, "target")
    _logins(main, target, protected=protected)
    _announced_target(main, saved_uid, protected=protected)
    _roster_identity(main, saved_uid, protected=protected)


def account_gate(report: Report, name: str) -> None:
    """Check a guard or seed case against the owned account's state.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The case report.
    name : str
        The case name, which ends in ``zero`` for the zero-access account.
    """
    key, expected_name, access = (
        (cases.ZERO_KEY, cases.ZERO_NAME, cases.ZERO_ACCESS)
        if name.endswith("zero")
        else (cases.PROTECTED_KEY, cases.PROTECTED_NAME, cases.PROTECTED_ACCESS)
    )
    if name.startswith("guard"):
        frame = reply(report, LOOKUP_REPLY_ID)
        require(
            frame["error"] == 1
            and field_map(frame)
            == {SERVER_NOTICE_FIELD: b"No account with login \xd2" + key + b"\xd3."},
            "Owned account key already exists",
        )
    else:
        require(
            reply(report, CREATE_REPLY_ID)["error"] == 0, "Owned account create failed"
        )
        frame = reply(report, READBACK_REPLY_ID)
        require(
            frame["error"] == 0
            and field_map(frame)
            == {
                102: expected_name,
                105: bytes(v ^ 255 for v in key),
                106: b"x",
                110: access,
            },
            "Owned account readback/access differs",
        )


def _accepted_probe(report: Report) -> None:
    """Check a probe whose Login107 the server accepted."""
    values = relevant(report, "main", kind=GET_USER_ACCESS, reply_marker=0)
    require(
        len(values) == 1 and field_map(values[0]) == {110: cases.ZERO_ACCESS},
        "Fresh target effective access differs",
    )
    require(
        len(relevant(report, "main", kind=AGREEMENT, reply_marker=0)) == 1,
        "Fresh agreement missing",
    )
    snapshots = relevant(report, "main", identifier=PROBE_ROSTER_ID, reply_marker=1)
    require(
        len(snapshots) == 1
        and any(r["name_hex"] == cases.ZERO_NAME.hex() for r in roster(snapshots[0])),
        "Fresh roster lacks owned target",
    )


def probe_gate(
    report: Report,
    accepted: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # called positionally
) -> None:
    """Check a probe's Login107 reply and the bytes it sent.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The case report.
    accepted : bool
        Whether the probe is expected to log in (after a kick without a ban).
    """
    response = reply(report, PROBE_REPLY_ID)
    if accepted:
        require(
            response["type"] == 0 and response["error"] == 0,
            "Fresh controlled Login107 did not succeed",
        )
        _accepted_probe(report)
    else:
        require(
            response["type"] == 0
            and response["error"] == 1
            and field_map(response) == {SERVER_NOTICE_FIELD: TEMP_TEXT},
            "Fresh Login107 temporary-ban error differs",
        )
        # Only the correlated Login107 reply is claimed. The complete TCP
        # capture, not this parsed-frame list, bounds any later observed tail.
    sends = [e["hex"] for e in report["events"] if e["event"] == "send"]
    require(
        len(sends) == (ACCEPTED_SENDS if accepted else REFUSED_SENDS)
        and sends[0] == TRTP_HELLO
        and sends[1]
        == cases.authentication(
            cases.ZERO_KEY, cases.ZERO_PASSWORD, name=cases.ZERO_NAME
        )["hex"],
        "Fresh TRTP/107 vector differs",
    )


def _events_of(report: Report, connection: str, event: str) -> bool:
    """Say whether a connection recorded an event.

    Returns
    -------
    bool
        Whether any event of that connection and kind is in the report.
    """
    return any(
        e["connection"] == connection and e["event"] == event for e in report["events"]
    )


def _protected_gate(report: Report) -> None:
    """Check that the protected target refused the kick and stayed live."""
    identity_before_110(
        report["frames"],
        bytes.fromhex(report["variables"]["target_uid"]),
        protected=True,
    )
    error = reply(report, KICK_REPLY_ID)
    text = field_map(error).get(SERVER_NOTICE_FIELD, b"")
    require(
        error["error"] == 1 and b"protected" in text.lower(),
        "Protected target kick was not rejected",
    )
    require(
        reply(report, TARGET_QUIET_REPLY_ID, "target")["error"] == 0
        and not relevant(report, "target", kind=DISCONNECT_MESSAGE)
        and not _events_of(report, "target", "eof"),
        "Protected target did not remain live",
    )
    require(
        _events_of(report, "target", "quiet"),
        "Protected target lacked post-500 bounded quiet barrier",
    )


def _kick_gate(report: Report, name: str) -> None:
    """Check a kick of an unprotected target, with or without a temporary ban."""
    identity_before_110(
        report["frames"],
        bytes.fromhex(report["variables"]["target_uid"]),
        protected=False,
    )
    target_notice = relevant(report, "target", kind=DISCONNECT_MESSAGE, reply_marker=0)
    require(
        len(target_notice) == int(name == "tempban"),
        "Kick notice cardinality differs",
    )
    if name == "tempban":
        require(
            field_map(target_notice[0]) == {101: TEMP_TEXT},
            "Temporary notice text differs",
        )
    require(_events_of(report, "target", "eof"), "Kicked target EOF absent")
    require(
        reply(report, KICK_REPLY_ID)["error"] == 0
        and len(relevant(report, "main", kind=USER_LEFT, reply_marker=0)) == 1,
        "Requester ACK/departure differs",
    )


def outcome_gate(report: Report, name: str) -> None:
    """Check a finished case against what its name says it observed.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The case report.
    name : str
        The case name.

    Raises
    ------
    ValueError
        If the case is incomplete, differs from its expectation, or is not a
        known expiry fixture case.
    """
    require(
        report["status"] == "completed"
        and report["completed_actions"] == len(cases.plans()[name]),
        f"{name} capture incomplete",
    )
    if name.startswith(("guard", "seed")):
        account_gate(report, name)
    elif name.endswith("probe"):
        probe_gate(report, name in ACCEPTING_PROBES)
    elif name == "protected":
        _protected_gate(report)
    elif name in UNPROTECTED_KICKS:
        _kick_gate(report, name)
    else:
        message = "Unrecognised expiry fixture case"
        raise ValueError(message)
