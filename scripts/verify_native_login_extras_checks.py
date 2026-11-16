"""Check one recorded login-extras case: its frames, replies and byte values.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import typing as typ

from native_banner_cases import GIF_B, URL
from native_login_extras_cases import CONFIGURED_URL, NAMES
from native_wire_names import (
    BANNER_MIN_VERSION,
    FIELD_ACCESS_BITMAP,
    FIELD_BANNER_LINK,
    FIELD_BANNER_TYPE,
    FIELD_DATA,
    FIELD_SERVER_NAME,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FIELD_UNNAMED_WORD,
    FIELD_VERSION,
    HTXF_MAGIC_HEX,
    TYPE_BANNER_METADATA,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import ADMIN, reply, selected
from verify_native_banners import fields
from verify_native_core import require

type Report = dict[str, typ.Any]

ACK = 0  # the type of a reply that carries no data of its own
REPORTED_VERSION = b"\0\xbe"
UNNAMED_WORD = b"\0\0"
BANNER_SIZE = b"\0\x3a"
REFERENCE_BYTES = 4
BANNER_ATTACH_TAIL = "0000000000020000"  # the size word, selector 2 and reserved word
EARLY_REPLY_IDS = [1, 90]
LATE_REPLY_IDS = [1, 2, 90]
EARLY_SHAPE = [
    (ACK, 1, 0),
    (TYPE_PRIVILEGES_NOTIFICATION, 0, 0),
    (TYPE_LOGIN_AGREEMENT, 0, 0),
]
LATE_SHAPE = [
    (ACK, 1, 0),
    (TYPE_LOGIN_AGREEMENT, 0, 0),
    (ACK, 1, 0),
    (TYPE_PRIVILEGES_NOTIFICATION, 0, 0),
]
WAITING_TYPES = [
    ACK,
    TYPE_LOGIN_AGREEMENT,
    ACK,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_BANNER_METADATA,
    ACK,
]
LIVENESS_ID = 90
ACCEPT_ID = 2
LIFETIME_SESSIONS = [
    ("observer", "name-a"),
    ("waiting", "name-a"),
    ("fresh", "name-b"),
]
BANNER_REQUEST_IDS = [10, 11]
BANNER_REPLIES = [(1, 0), (10, 0), (11, 0)]


def login_ack(frame: Report, name: bytes) -> None:
    """Check a login ACK's correlation, status and extra values."""
    expected = {FIELD_VERSION: REPORTED_VERSION, FIELD_UNNAMED_WORD: UNNAMED_WORD}
    if name:
        expected[FIELD_SERVER_NAME] = name
    require(
        frame["is_reply"] == 1 and frame["id"] == 1 and frame["error"] == 0,
        "Login extra ACK correlation/status differs",
    )
    require(fields(frame) == expected, "Configured login-extra values differ")


def login_shape(*, early: bool, advertised: bool) -> list[tuple[int, int, int]]:
    """Build the (type, reply, error) shape of a configured login.

    Returns
    -------
    list[tuple[int, int, int]]
        The frames that the case must have received, in order.
    """
    shape = list(EARLY_SHAPE if early else LATE_SHAPE)
    if advertised:
        shape.append((TYPE_BANNER_METADATA, 0, 0))
    shape.append((ACK, 1, 0))
    return shape


def check_configured(report: Report, expected: Report, agreement: bytes) -> Report:
    """Check one configured login: its frames, extras, agreement and banner.

    Returns
    -------
    dict[str, typing.Any]
        The expectation's early flag and version, and whether a banner was sent.
    """
    frames = report["frames"]
    early, version = expected["early"], expected["version"]
    advertised = (
        not early
        and version is not None
        and version >= BANNER_MIN_VERSION
        and expected["phase"] != "none"
    )
    require(
        [(f["type"], f["is_reply"], f["error"]) for f in frames]
        == login_shape(early=early, advertised=advertised),
        "Configured login/banner sequence differs",
    )
    login_ack(frames[0], bytes.fromhex(expected["name_hex"]))
    require(
        [f["id"] for f in frames if f["is_reply"]]
        == (EARLY_REPLY_IDS if early else LATE_REPLY_IDS),
        "Configured reply IDs differ",
    )
    require(
        fields(next(f for f in frames if f["type"] == TYPE_LOGIN_AGREEMENT))
        == {FIELD_DATA: agreement},
        "Configured agreement changed",
    )
    require(
        fields(next(f for f in frames if f["type"] == TYPE_PRIVILEGES_NOTIFICATION))
        == {FIELD_ACCESS_BITMAP: ADMIN},
        "Configured privileges changed",
    )
    if advertised:
        tag, link = (
            (b"URL ", CONFIGURED_URL) if expected["phase"] == "url" else (b"GIFf", URL)
        )
        require(
            fields(next(f for f in frames if f["type"] == TYPE_BANNER_METADATA))
            == {FIELD_BANNER_TYPE: tag, FIELD_BANNER_LINK: link},
            "Configured banner metadata differs",
        )
    require(fields(reply(report, LIVENESS_ID)) == {}, "Configured liveness ACK differs")
    if not early:
        require(
            fields(reply(report, ACCEPT_ID)) == {},
            "Acceptance ACK unexpectedly refreshes login extras",
        )
    return {"early": early, "version": version, "advertised": advertised}


def check_sessions(report: Report, agreement: bytes) -> None:
    """Check each session's login extras, agreement and later frames."""
    for connection, label in LIFETIME_SESSIONS:
        frames = selected(report, connection)
        login_ack(frames[0], NAMES[label])
        require(
            fields(next(f for f in frames if f["type"] == TYPE_LOGIN_AGREEMENT))
            == {FIELD_DATA: agreement},
            "Lifetime agreement changed",
        )
        for frame in frames[1:]:
            require(
                not ({FIELD_UNNAMED_WORD, FIELD_SERVER_NAME} & set(fields(frame))),
                "Existing-session login extras were refreshed",
            )


def check_lifetime(report: Report, agreement: bytes) -> Report:
    """Check that a name change leaves existing sessions' login extras alone.

    Returns
    -------
    dict[str, typing.Any]
        The old and the fresh server name, in hexadecimal.
    """
    check_sessions(report, agreement)
    require(
        fields(reply(report, ACCEPT_ID, "waiting")) == {},
        "Waiting acceptance refreshed its login extras",
    )
    require(
        fields(reply(report, LIVENESS_ID, "waiting")) == {},
        "Waiting session failed to complete after the change",
    )
    for identifier in [LIVENESS_ID, 91]:
        require(
            fields(reply(report, identifier, "observer")) == {},
            "Existing online session lost liveness",
        )
    waiting = selected(report, "waiting")
    require(
        [f["type"] for f in waiting] == WAITING_TYPES,
        "Waiting name-change completion differs",
    )
    require(
        fields(next(f for f in waiting if f["type"] == TYPE_BANNER_METADATA))
        == {FIELD_BANNER_TYPE: b"GIFf", FIELD_BANNER_LINK: URL},
        "Name-only save changed banner metadata",
    )
    return {
        "old_name_hex": NAMES["name-a"].hex(),
        "fresh_name_hex": NAMES["name-b"].hex(),
    }


def check_banner_reference(report: Report, identifier: int) -> str:
    """Check one banner reference reply, its stream and its attach greeting.

    Returns
    -------
    str
        The reference, in hexadecimal.
    """
    response = fields(reply(report, identifier))
    require(
        set(response) == {FIELD_TRANSFER_REFERENCE, FIELD_TRANSFER_SIZE}
        and response[FIELD_TRANSFER_SIZE] == BANNER_SIZE,
        "Banner reference/size fields differ",
    )
    reference = response[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and int.from_bytes(reference, "big") != 0,
        "Banner reference equals zero login value161",
    )
    connection = f"data{identifier}"
    require(
        report["streams"][connection]["received_hex"] == GIF_B.hex(),
        "Configured banner bytes changed",
    )
    require(
        report["streams"][connection]["sent_hex"]
        == HTXF_MAGIC_HEX + reference.hex() + BANNER_ATTACH_TAIL,
        "Banner attach reference differs",
    )
    return reference.hex()


def check_downloads(report: Report, agreement: bytes) -> Report:
    """Check the banner downloads that follow a configured login.

    Returns
    -------
    dict[str, typing.Any]
        The login value and the banner references, in hexadecimal.
    """
    frames = selected(report, "main")
    login_ack(frames[0], NAMES["name-b"])
    require(
        fields(frames[1]) == {FIELD_ACCESS_BITMAP: ADMIN}
        and fields(frames[2]) == {FIELD_DATA: agreement},
        "Banner-reference login bootstrap differs",
    )
    require(
        [(f["id"], f["error"]) for f in frames if f["is_reply"]] == BANNER_REPLIES,
        "Banner-reference replies differ",
    )
    references = [check_banner_reference(report, i) for i in BANNER_REQUEST_IDS]
    return {"login_value_hex": "0000", "banner_reference_hex": references}
