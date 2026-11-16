"""Check the meaning of the room notifications and dispatch each scenario's checks.

The outcome of each scenario lives in verify_native_rooms_scenarios. The
scenarios are dispatched by two matches, rather than one, to keep each function
within the complexity limit; each name matches at most one case.
"""

import native_room_cases as cases
from native_wire_names import FIELD_ICON, FIELD_NAME, FIELD_USER_ID
from verify_native_core import require
from verify_native_rooms_reports import identities, pushes
from verify_native_rooms_scenarios import (
    check_basics,
    check_concurrent,
    check_concurrent_snapshots,
    check_create_invites,
    check_formatting,
    check_invites,
    check_lifecycle,
    check_refusals,
    check_topics,
)
from verify_native_rooms_wire import (
    FIELD_ROOM,
    FIELD_STATUS,
    ROOM_JOIN_NOTICE,
    ROOM_LEAVE_NOTICE,
)

OWNER_STATUS = 0x12  # the status that the owner's join carries
ZERO_ROLE_STATUS = 0x20  # the status that the zero-access role's join carries
REFUSED_STATUS = 8  # the status of the reader who refused private chats


def semantic(name: str, report: dict) -> None:
    """Check the room notifications and the outcome of the scenario ``name``.

    Parameters
    ----------
    name : str
        The name of the scenario that the report belongs to.
    report : dict
        The retained report of the scenario.
    """
    room, ids = identities(report)
    _check_notifications(name, report, room, ids)
    _check_first_scenarios(name, report, room, ids)
    _check_second_scenarios(name, report, room, ids)


def _check_first_scenarios(
    name: str, report: dict, room: bytes, ids: dict[str, bytes]
) -> None:
    """Check the outcome of the scenarios that come first in the chronology.

    Parameters
    ----------
    name : str
        The name of the scenario that the report belongs to.
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    match name:
        case "basics":
            check_basics(report, room, ids)
        case "topics":
            check_topics(report, room, ids)
        case "lifecycle":
            check_lifecycle(report, room, ids)
        case "concurrent":
            check_concurrent_snapshots(report, ids)
            check_concurrent(report, ids)


def _check_second_scenarios(
    name: str, report: dict, room: bytes, ids: dict[str, bytes]
) -> None:
    """Check the outcome of the scenarios that come after the first group.

    Parameters
    ----------
    name : str
        The name of the scenario that the report belongs to.
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    match name:
        case "create_invites":
            check_create_invites(report, room, ids)
        case "invites":
            check_invites(report, room, ids)
        case "refusals":
            check_refusals(report, room, ids)
        case "formatting":
            check_formatting(report, room)


def _join_fields(name: str, actor: str) -> dict:
    """Return the fields that a join notification carries for ``actor``.

    Parameters
    ----------
    name : str
        The name of the scenario, which decides the refused status.
    actor : str
        The label of the participant who joined.

    Returns
    -------
    dict
        The icon, the status and the name of the participant.
    """
    icon = 1 if actor == "main" else 30 + list(cases.ROLES).index(actor)
    status = (
        OWNER_STATUS
        if actor == "main"
        else ZERO_ROLE_STATUS
        if actor == "zero"
        else REFUSED_STATUS
        if name == "refusals" and actor == "reader"
        else 0
    )
    return {
        FIELD_ICON: icon.to_bytes(2, "big"),
        FIELD_STATUS: status.to_bytes(2, "big"),
        FIELD_NAME: b"framing-fixture"
        if actor == "main"
        else b"Room30-" + actor.encode(),
    }


def _check_notifications(
    name: str, report: dict, room: bytes, ids: dict[str, bytes]
) -> None:
    """Check that every join and leave notification names the room and a member.

    Parameters
    ----------
    name : str
        The name of the scenario that the report belongs to.
    report : dict
        The retained report of the scenario.
    room : bytes
        The room identifier.
    ids : dict[str, bytes]
        The identifier of the owner and of each role.
    """
    for connection in ["main", *cases.ROLES]:
        for kind in [ROOM_JOIN_NOTICE, ROOM_LEAVE_NOTICE]:
            for event in pushes(report, connection, kind):
                require(
                    event.get(FIELD_ROOM) == room
                    and event.get(FIELD_USER_ID) in ids.values(),
                    "Room event identity differs",
                )
                actor = next(
                    label for label, uid in ids.items() if uid == event[FIELD_USER_ID]
                )
                expected_event = {FIELD_ROOM: room, FIELD_USER_ID: ids[actor]}
                if kind == ROOM_JOIN_NOTICE:
                    expected_event.update(_join_fields(name, actor))
                require(
                    event == expected_event,
                    "Room membership notification schema differs",
                )
