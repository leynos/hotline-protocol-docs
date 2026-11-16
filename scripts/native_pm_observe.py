"""Build the two-session private-message observation of the A26 preparation."""

import dataclasses as dc
import typing as typ

from native_auth_cases import authentication
from native_plan import close, login, packet, read, send
from native_pm_steps import UID_BYTES, barrier, settings, variable_message
from native_wire_names import (
    FIELD_DATA,
    FIELD_OPTIONS,
    FIELD_QUOTE,
    FIELD_USER_ID,
    TYPE_GET_USER_ROSTER,
    TYPE_MESSAGE_NOTIFICATION,
    TYPE_PRESENCE_UPDATE,
    TYPE_SEND_PRIVATE_MESSAGE,
)

type Json = dict[str, typ.Any]

MAIN = b"PM-Main-A26"
PEER = b"PM-Peer-A26"
QUOTE = b"quote-a26"
MAIN_UID_OFFSET = 26  # offset of the main user id in the 300 reply
ADMIN_LOGIN = b"admin"
ADMIN_CREDENTIAL = b"mothra19"
ROSTER_ID = 10
MAIN_SETTINGS_ID = 20
PEER_SETTINGS_ID = 21
STATE_SETTINGS_ID = 30  # plus the case index, for the main session
PEER_STATE_SETTINGS_ID = 40  # plus the case index, for the peer session
REQUEST_ID = 60  # plus the case index
BARRIER_ID = 160  # plus the case index
FINAL_MAIN_SETTINGS_ID = 90
FINAL_PEER_SETTINGS_ID = 91
AUTO_REPLY_OPTION = 4  # the peer option value that enables the automatic reply
AUTO_REPLY_TEXT = b"pm-a26-auto"


@dc.dataclass(frozen=True, slots=True)
class Case:
    """One private-message case: what is sent and how the two sides are set.

    Attributes
    ----------
    option : int
        The PM option field of the request.
    text : bytes
        The message text.
    quote : bytes
        The quoted text, if any.
    sender_push : int
        How many 104 notifications the sender should receive.
    recipient_push : int
        How many 104 notifications the recipient should receive.
    sender : str
        The session that sends: ``main`` or ``peer``.
    """

    option: int
    text: bytes
    quote: bytes = b""
    sender_push: int = 0
    recipient_push: int = 0
    sender: str = "main"


CASES = {
    "direct-quoted": Case(1, b"pm-a26-direct", QUOTE, recipient_push=1),
    "recipient-refuses": Case(1, b"pm-a26-refused", sender_push=1),
    "auto-and-original": Case(1, b"pm-a26-with-auto", sender_push=1, recipient_push=1),
    "sender-refuses": Case(1, b"pm-a26-sender-refuses"),
    "option-two": Case(2, b"pm-a26-option-two", recipient_push=1),
    "option-three": Case(3, b"pm-a26-option-three", recipient_push=1, sender="peer"),
    "empty": Case(1, b""),
}
STATES = [(0, 0), (0, 1), (0, 4), (1, 1), (0, 0), (0, 0), (0, 0)]


def open_sessions() -> list[Json]:
    """Log in the main session, then the peer, and wait for the peer's arrival.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    steps = [
        *login(),
        send(packet(TYPE_GET_USER_ROSTER, ROSTER_ID)),
        read(
            match_frame={"is_reply": 1, "id": ROSTER_ID},
            save={"name": "main_uid", "offset": MAIN_UID_OFFSET, "size": UID_BYTES},
        ),
    ]
    steps += [{**step, "connection": "peer"} for step in login()[:3]]
    return [
        *steps,
        authentication(ADMIN_LOGIN, ADMIN_CREDENTIAL, name=PEER, connection="peer"),
        read("peer"),
        read("peer"),
        read("peer"),
        read(
            "main",
            match_frame={"type": TYPE_PRESENCE_UPDATE},
            save_fields={"peer_uid": FIELD_USER_ID},
        ),
    ]


def change_settings(
    index: int, state: tuple[int, int], previous: tuple[int, int]
) -> list[Json]:
    """Reconfigure the sessions for a case whose options differ from the last.

    Parameters
    ----------
    index : int
        The case's position.
    state : tuple[int, int]
        The main and peer options wanted.
    previous : tuple[int, int]
        The options in force.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps; none when nothing changes.
    """
    steps: list[Json] = []
    if state[0] != previous[0]:
        steps += settings("main", STATE_SETTINGS_ID + index, MAIN, state[0])
    if state[1] != previous[1]:
        auto = AUTO_REPLY_TEXT if state[1] == AUTO_REPLY_OPTION else b""
        steps += settings("peer", PEER_STATE_SETTINGS_ID + index, PEER, state[1], auto)
    return steps


def send_case(index: int, case: Case) -> list[Json]:
    """Send one case's message and read what it should provoke.

    Parameters
    ----------
    index : int
        The case's position.
    case : Case
        The case.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps, ending with a barrier.
    """
    fields = [
        (FIELD_OPTIONS, case.option.to_bytes(2, "big")),
        (FIELD_DATA, case.text),
    ]
    if case.quote:
        fields.append((FIELD_QUOTE, case.quote))
    identifier = REQUEST_ID + index
    sender = case.sender
    recipient = "peer" if sender == "main" else "main"
    uid = "peer_uid" if recipient == "peer" else "main_uid"
    notification = {"type": TYPE_MESSAGE_NOTIFICATION}
    steps = [
        variable_message(TYPE_SEND_PRIVATE_MESSAGE, identifier, uid, fields, sender)
    ]
    steps += [read(sender, match_frame={"is_reply": 1, "id": identifier})]
    steps += [read(sender, match_frame=notification) for _ in range(case.sender_push)]
    steps += [
        read(recipient, match_frame=notification) for _ in range(case.recipient_push)
    ]
    return [*steps, *barrier(BARRIER_ID + index)]


def observe() -> list[Json]:
    """Build the observation: log in, send each case, then restore the settings.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps.
    """
    steps = open_sessions()
    steps += settings("main", MAIN_SETTINGS_ID, MAIN, 0)
    steps += settings("peer", PEER_SETTINGS_ID, PEER, 0)
    previous = (0, 0)
    for index, case in enumerate(CASES.values()):
        steps += change_settings(index, STATES[index], previous)
        previous = STATES[index]
        steps += send_case(index, case)
    steps += settings("main", FINAL_MAIN_SETTINGS_ID, MAIN, 0)
    steps += settings("peer", FINAL_PEER_SETTINGS_ID, PEER, 0)
    return [*steps, close("peer"), close()]
