"""Check the native login exchange that the shx peer drove."""

import typing as typ

from native_auth_steps import complement
from native_wire_names import (
    FIELD_DATA,
    FIELD_ERROR_TEXT,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_SERVER_NAME,
    FIELD_UNNAMED_WORD,
    FIELD_USER_RECORD,
    FIELD_VERSION,
    HANDSHAKE_REPLY_BYTES,
    HANDSHAKE_REPLY_HEX,
    HANDSHAKE_REQUEST_HEX,
    ROSTER_HEADER_BYTES,
    ROSTER_NAME_LENGTH_START,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_DOWNLOAD_FILE,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_LOGIN,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_SEND_CHAT,
)
from verify_native_core import (
    FIXTURE_UNNAMED_WORD_REPLY,
    FIXTURE_VERSION_REPLY,
    require,
)
from verify_native_shx_frames import HANDSHAKE_REQUEST_BYTES, fields, frames
from verify_native_shx_operations import Session, check_operations
from verify_native_shx_packets import CONTROL_PORT

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

PEER_ICON = b"\x01\xf4"  # the `-i 500` of the login command
PEER_NAME = b"shx-peer-a"
PEER_PASSWORD = b"mothra19"
WRONG_PASSWORD = b"wrong-shx-pass"
FAILED_LOGIN = b"Incorrect login."
LOGIN_ID = 1
ROSTER_TYPES = [TYPE_LOGIN, TYPE_GET_USER_ROSTER]
OPERATION_TYPES = {
    "basic-empty-name": [*ROSTER_TYPES, TYPE_SEND_CHAT],
    "root-listing": [*ROSTER_TYPES, TYPE_LIST_FILES],
    "fork-download": [*ROSTER_TYPES, TYPE_LIST_FILES, TYPE_DOWNLOAD_FILE],
    "ambiguous-text": ROSTER_TYPES,
}
BOOTSTRAP_TYPES = [TYPE_PRIVILEGES_NOTIFICATION, TYPE_LOGIN_AGREEMENT]


class SemanticsOptions(typ.TypedDict, total=False):
    """The choices of a semantic check; each defaults to off.

    ``kind`` names the case whose checks apply when it is not the directory
    name, and ``login_name`` is the server name that the login reply carries.
    """

    kind: str | None
    login_name: bytes


def open_session(case: Path, connections: list[Report], name: str) -> Session:
    """Check the handshake and the login request of a control connection.

    Returns
    -------
    Session
        The control connection's frames and the terminal output.
    """
    control = next(c for c in connections if c["endpoint"] == CONTROL_PORT)
    require(
        control["sent"].startswith(bytes.fromhex(HANDSHAKE_REQUEST_HEX)),
        "Peer handshake changed",
    )
    require(
        control["received"].startswith(bytes.fromhex(HANDSHAKE_REPLY_HEX)),
        "Native handshake changed",
    )
    requests = frames(control["sent"][HANDSHAKE_REQUEST_BYTES:])
    replies = frames(control["received"][HANDSHAKE_REPLY_BYTES:])
    login = requests[0]
    credentials = WRONG_PASSWORD if name == "wrong-password" else PEER_PASSWORD
    require(
        (login["type"], login["id"], login["is_reply"]) == (TYPE_LOGIN, LOGIN_ID, 0),
        "Basic peer login header changed",
    )
    require(
        fields(login)
        == {
            FIELD_ICON: PEER_ICON,
            FIELD_LOGIN: complement(b"admin"),
            FIELD_PASSWORD: complement(credentials),
            FIELD_NAME: PEER_NAME,
        },
        "Peer login fields changed, including absent version160",
    )
    terminal = (case / "stdout.bin").read_bytes()
    return Session(case, name, connections, requests, replies, terminal)


def check_failed_login(session: Session) -> Report:
    """Check that a wrong password stopped the session with the native error.

    Returns
    -------
    dict[str, typing.Any]
        The marker of a failed login.
    """
    requests, replies = session.requests, session.replies
    require(
        len(requests) == len(replies) == len(session.connections) == 1,
        "Failed login continued",
    )
    require(
        replies[0]["error"] == 1
        and replies[0]["is_reply"] == 1
        and replies[0]["id"] == LOGIN_ID
        and fields(replies[0]) == {FIELD_ERROR_TEXT: FAILED_LOGIN},
        "Native login error differs",
    )
    require(
        b"login failed?" in session.terminal and FAILED_LOGIN in session.terminal,
        "Peer did not report login failure",
    )
    return {"failed_login": True}


def check_bootstrap(session: Session, agreement: bytes, login_name: bytes) -> None:
    """Check the login reply, the privileges and the agreement that follow it."""
    requests, replies = session.requests, session.replies
    extras = {
        FIELD_VERSION: FIXTURE_VERSION_REPLY,
        FIELD_UNNAMED_WORD: FIXTURE_UNNAMED_WORD_REPLY,
        **({FIELD_SERVER_NAME: login_name} if login_name else {}),
    }
    require(
        replies[0]["error"] == 0
        and replies[0]["id"] == LOGIN_ID
        and replies[0]["is_reply"] == 1
        and fields(replies[0]) == extras,
        "Native login extras differ",
    )
    require(
        [r["type"] for r in replies[1:3]] == BOOTSTRAP_TYPES
        and fields(replies[2]) == {FIELD_DATA: agreement},
        "Native privilege/agreement bootstrap differs",
    )
    require(
        [r["type"] for r in requests[:2]] == ROSTER_TYPES,
        "Peer automatic roster request differs",
    )
    require(
        all(r["type"] != TYPE_ACCEPT_AGREEMENT for r in requests),
        "Unexpected late login acceptance",
    )


def check_roster(session: Session) -> list[bytes]:
    """Check the roster reply and that the peer reported its login.

    Returns
    -------
    list[bytes]
        The names in the roster.
    """
    roster = next(
        r
        for r in session.replies
        if r["is_reply"] and r["id"] == session.requests[1]["id"]
    )
    names = []
    for f in roster["fields"]:
        data = bytes.fromhex(f["hex"])
        require(
            f["id"] == FIELD_USER_RECORD
            and len(data) >= ROSTER_HEADER_BYTES
            and int.from_bytes(
                data[ROSTER_NAME_LENGTH_START:ROSTER_HEADER_BYTES], "big"
            )
            == len(data) - ROSTER_HEADER_BYTES,
            "Native roster record differs",
        )
        names.append(data[ROSTER_HEADER_BYTES:])
    require(
        PEER_NAME in names and b"login successful" in session.terminal,
        "Peer roster/login failed",
    )
    return names


def check_semantics(
    case: Path,
    connections: list[Report],
    agreement: bytes,
    **options: typ.Unpack[SemanticsOptions],
) -> Report:
    """Check what one peer session sent and received.

    Returns
    -------
    dict[str, typing.Any]
        The request and reply types and the roster names, or a failed-login marker.
    """
    name = options.get("kind") or case.name
    session = open_session(case, connections, name)
    if name == "wrong-password":
        return check_failed_login(session)
    check_bootstrap(session, agreement, options.get("login_name", b""))
    names = check_roster(session)
    require(
        all(r["error"] == 0 for r in session.replies),
        "Unexpected native operation error",
    )
    require(
        [r["type"] for r in session.requests] == OPERATION_TYPES[name],
        "Peer operation sequence differs",
    )
    check_operations(session)
    return {
        "request_types": [r["type"] for r in session.requests],
        "received_types": [r["type"] for r in session.replies],
        "roster_names_hex": [n.hex() for n in names],
    }
