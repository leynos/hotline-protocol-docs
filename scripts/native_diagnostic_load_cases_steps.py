"""Build the steps of the bounded native 303 transfer-state observations.

Part of the diagnostic-load planner (``native_diagnostic_load_cases``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below.
"""

import typing as typ

from native_cleanup_cases import data_fork
from native_diagnostic_cases import diagnostic_request
from native_plan import close, connect, packet, payload, read, send
from native_queue_cases import attach, cancel, session
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    TYPE_DOWNLOAD_FILE,
    TYPE_GET_FILE_INFO,
    TYPE_GET_USER_ROSTER,
    TYPE_LIST_FILES,
    TYPE_UPLOAD_FILE,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Step = dict[str, typ.Any]

NAME = b"m-diag37-" + b"x" * 22
BODY = file_stream(data_fork(), resource_fork())
# The offset and size of the admin's user id in the roster reply.
ADMIN_UID_OFFSET = 26
ADMIN_UID_SIZE = 2
ACCOUNTS_REQUEST = 348
SIZE_BYTES = 4
UPLOAD_EOF_SECONDS = 60
DRAIN_EOF_SECONDS = 30
HTXF_MAGIC_HEX = "48545846"
# The boundary case runs this many transfers in each state.
BOUNDARY_ACTIVE = 8
BOUNDARY_QUEUED = 8
# The index of the queued transfer after which the first diagnostic is taken.
BOUNDARY_DIAGNOSTIC_AFTER = 3
# The 303 request names a user; this value names every user at once.
ALL_USERS = b"\xff\xff"


def exchange(kind: int, identifier: int, fields: list[tuple[int, bytes]]) -> list[Step]:
    """Send one request on the admin connection and read its reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the read step.
    """
    return [
        send(packet(kind, identifier, payload(fields)), "a"),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def request(owner: str, identifier: int, variable: str) -> list[Step]:
    """Request the owned file as a download and save its reference and size.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the read step that saves ``variable``.
    """
    return [
        send(
            packet(TYPE_DOWNLOAD_FILE, identifier, payload([(FIELD_FILE_NAME, NAME)])),
            owner,
        ),
        read(
            owner,
            match_frame={"is_reply": 1, "id": identifier},
            save_fields={
                variable: FIELD_TRANSFER_REFERENCE,
                variable + "_size": FIELD_TRANSFER_SIZE,
            },
        ),
    ]


def roster(identifier: int = 14) -> list[Step]:
    """Request the roster and save the admin's user id.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the read step that saves ``admin_uid``.
    """
    return [
        send(packet(TYPE_GET_USER_ROSTER, identifier), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save={
                "name": "admin_uid",
                "offset": ADMIN_UID_OFFSET,
                "size": ADMIN_UID_SIZE,
            },
        ),
    ]


def diagnostic(identifier: int, uid: str | bytes = "admin_uid") -> list[Step]:
    """Request the 303 diagnostic for a user and read the reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        The send step and the read step.
    """
    return [
        diagnostic_request("a", identifier, uid),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def preflight() -> list[Step]:
    """Plan the read-only look at the accounts, the files and the idle 303.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the case.
    """
    return (
        session("a")
        + exchange(ACCOUNTS_REQUEST, 10, [])
        + exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
        + exchange(TYPE_GET_FILE_INFO, 12, [(FIELD_FILE_NAME, NAME)])
        + roster()
        + diagnostic(15)
        + [close("a")]
    )


def seed() -> list[Step]:
    """Plan the upload of the owned file.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the case.
    """
    size = len(BODY).to_bytes(SIZE_BYTES, "big")
    steps = [
        *session("a"),
        send(
            packet(
                TYPE_UPLOAD_FILE,
                10,
                payload([(FIELD_FILE_NAME, NAME), (FIELD_TRANSFER_SIZE, size)]),
            ),
            "a",
        ),
        read(
            "a",
            match_frame={"is_reply": 1, "id": 10},
            save_field={"name": "upload_ref", "id": FIELD_TRANSFER_REFERENCE},
        ),
        connect("upload", "data"),
        send(
            HTXF_MAGIC_HEX + "{upload_ref}" + size.hex() + "00000000" + BODY.hex(),
            "upload",
        ),
        {"op": "read_eof", "connection": "upload", "timeout": UPLOAD_EOF_SECONDS},
        close("upload"),
    ]
    return (
        steps
        + exchange(TYPE_GET_FILE_INFO, 11, [(FIELD_FILE_NAME, NAME)])
        + [close("a")]
    )


def active_queue() -> list[Step]:
    """Plan one active and one queued transfer, observed by the 303 diagnostic.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the case.
    """
    steps = session("a") + roster(10)
    steps += request("a", 11, "active")
    steps += attach("active")
    steps += request("a", 12, "queued")
    steps += diagnostic(13)
    steps += diagnostic(14, ALL_USERS)
    steps += cancel("a", 15, "queued") + cancel("a", 16, "active")
    steps += [
        {"op": "read_eof", "connection": "active", "timeout": DRAIN_EOF_SECONDS},
        close("active"),
    ]
    return steps + diagnostic(17) + [close("a")]


def boundary() -> list[Step]:
    """Plan the transfers at the queue boundary, observed by the 303 diagnostic.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps of the case.
    """
    steps = session("a") + roster(10)
    for index in range(BOUNDARY_ACTIVE):
        steps += request("a", 20 + index, f"active{index}")
        steps += attach(f"active{index}")
    for index in range(BOUNDARY_QUEUED):
        steps += request("a", 40 + index, f"queued{index}")
        if index == BOUNDARY_DIAGNOSTIC_AFTER:
            steps += diagnostic(60)
    steps += diagnostic(61)
    for index in reversed(range(BOUNDARY_QUEUED)):
        steps += cancel("a", 70 + index, f"queued{index}")
    for index in reversed(range(BOUNDARY_ACTIVE)):
        steps += cancel("a", 80 + index, f"active{index}")
        steps += [
            {
                "op": "read_eof",
                "connection": f"active{index}",
                "timeout": DRAIN_EOF_SECONDS,
            },
            close(f"active{index}"),
        ]
    return steps + diagnostic(90) + [close("a")]


CASES: cabc.Mapping[str, cabc.Callable[[], list[Step]]] = {
    "preflight": preflight,
    "seed": seed,
    "active-queue": active_queue,
    "boundary": boundary,
}
