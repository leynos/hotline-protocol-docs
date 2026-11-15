"""Prepare multi-chunk native download cleanup and completion races."""

from native_plan import Action, close, connect, eof, packet, payload, read, send
from native_queue_cases import Case, attach, cancel, session
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    TYPE_DOWNLOAD_FILE,
    TYPE_GET_FILE_INFO,
    TYPE_UPLOAD_FILE,
)

# prepare_native_cases imports downloads, seed and upload_cleanup;
# verify_native_cleanup imports those with FILENAME and data_fork; and
# native_diagnostic_load_cases (and its as-run copy under evidence/) imports
# data_fork.
__all__ = ["FILENAME", "data_fork", "downloads", "seed", "upload_cleanup"]

type Cases = dict[str, Case]

FILENAME = b"mothra-race-fixture"
UPLOAD_FILENAME = b"mothra-214-upload"
UPLOAD_DATA = b"data-fork\r\n\x00\xff"
FORK_PERIOD = 256  # the data fork repeats the byte values 0 to 255
FORK_REPEATS = 4096  # so the baseline stream spans many transfer chunks
SIZE_BYTES = 4
UPLOAD_TAIL_HEX = "00000000"  # the word after the size in an upload greeting
STALE_TAIL_HEX = "0000000000000000"  # eight zero bytes after a download reference
REQUEST_ID = 10
LOOKUP_ID = 11  # the file-info request after the first upload
CANCEL_IDS = (11, 12, 13)  # the upload cleanup exchange numbers
OWNER_CANCEL_ID = 21
DUPLICATE_CANCEL_ID = 22
NONOWNER_CANCEL_ID = 20
PARTIAL_PREFIX = 1024  # bytes read before a partial variant cancels
READ_SECONDS = 30
QUIET_SECONDS = 3


def data_fork() -> bytes:
    """Build the data fork of the race fixture.

    Returns
    -------
    bytes
        The byte values 0 to 255, repeated 4096 times.
    """
    return bytes(range(FORK_PERIOD)) * FORK_REPEATS


def upload_request(identifier: int, filename: bytes, size: int) -> list[Action]:
    """Plan an upload request and the read of the reference it returns.

    Returns
    -------
    list[native_plan.Action]
        The 203 send and the reply read that saves the reference.
    """
    fields = [
        (FIELD_FILE_NAME, filename),
        (FIELD_TRANSFER_SIZE, size.to_bytes(SIZE_BYTES, "big")),
    ]
    return [
        send(packet(TYPE_UPLOAD_FILE, identifier, payload(fields)), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": identifier},
            save_field={"name": "reference", "id": FIELD_TRANSFER_REFERENCE},
        ),
    ]


def push_body(body: bytes) -> list[Action]:
    """Plan an upload connection that sends the whole body and closes.

    Returns
    -------
    list[native_plan.Action]
        The connect, the greeting with the body, end of stream and close.
    """
    greeting = (
        HTXF_MAGIC_HEX
        + "{reference}"
        + len(body).to_bytes(SIZE_BYTES, "big").hex()
        + UPLOAD_TAIL_HEX
        + body.hex()
    )
    return [
        connect("upload", "data"),
        send(greeting, "upload"),
        eof("upload"),
        close("upload"),
    ]


def info_request(identifier: int, filename: bytes) -> list[Action]:
    """Plan a file-info request and the read of its reply.

    Returns
    -------
    list[native_plan.Action]
        The 206 send and the reply read.
    """
    return [
        send(
            packet(
                TYPE_GET_FILE_INFO, identifier, payload([(FIELD_FILE_NAME, filename)])
            ),
            "a",
        ),
        read("a", match_frame={"is_reply": 1, "id": identifier}),
    ]


def seed() -> Cases:
    """Plan the upload that stores the race fixture.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The ``cleanup-seed`` case.
    """
    body = file_stream(data_fork(), resource_fork())
    steps = [
        *session("a"),
        *upload_request(REQUEST_ID, FILENAME, len(body)),
        *push_body(body),
        *info_request(LOOKUP_ID, FILENAME),
        close("a"),
    ]
    return {
        "cleanup-seed": (
            steps,
            {"kind": "cleanup-seed", "data_bytes": len(data_fork())},
        )
    }


def upload_cleanup() -> Cases:
    """Plan cleanup requests around a pending ordinary upload (214 leaves it).

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The ``cleanup-pending-upload`` case.
    """
    first, second, third = CANCEL_IDS
    body = file_stream(UPLOAD_DATA, resource_fork())
    steps = [
        *session("a"),
        *upload_request(REQUEST_ID, UPLOAD_FILENAME, len(body)),
        *cancel("a", first, "reference"),
        *push_body(body),
        *info_request(second, UPLOAD_FILENAME),
        *cancel("a", third, "reference"),
        close("a"),
    ]
    return {
        "cleanup-pending-upload": (
            steps,
            {"kind": "cleanup-upload", "name_hex": UPLOAD_FILENAME.hex()},
        )
    }


def download_request() -> list[Action]:
    """Plan the download request and the read of its reference and size.

    Returns
    -------
    list[native_plan.Action]
        The 202 send and the reply read that saves both fields.
    """
    return [
        send(
            packet(
                TYPE_DOWNLOAD_FILE,
                REQUEST_ID,
                payload([(FIELD_FILE_NAME, FILENAME)]),
            ),
            "a",
        ),
        read(
            "a",
            match_frame={"is_reply": 1, "id": REQUEST_ID},
            save_fields={
                "reference": FIELD_TRANSFER_REFERENCE,
                "size": FIELD_TRANSFER_SIZE,
            },
        ),
    ]


def read_reference(**options: int | str) -> Action:
    """Plan a read on the downloading connection.

    Returns
    -------
    native_plan.Action
        A ``read`` action in the key order the plans have always had.
    """
    return {
        "op": "read",
        "connection": "reference",
        **options,
        "timeout": READ_SECONDS,
    }


def finish_variant(name: str) -> list[Action]:
    """Plan the reads that follow the attachment, which depend on the variant.

    Returns
    -------
    list[native_plan.Action]
        The cleanup from the non-owner (when there is one) and the reads.
    """
    if name in {"baseline", "nonowner"}:
        steps = []
        if name == "nonowner":
            steps = cancel("b", NONOWNER_CANCEL_ID, "reference")
        return [
            *steps,
            read_reference(size_from="size"),
            {"op": "expect_quiet", "connection": "reference", "timeout": QUIET_SECONDS},
        ]
    if name.startswith("partial"):
        return [read_reference(size=PARTIAL_PREFIX)]
    return []


def stale_attachment() -> list[Action]:
    """Plan an attempt to reuse the removed reference.

    Returns
    -------
    list[native_plan.Action]
        The connect, the greeting, end of stream and close.
    """
    return [
        connect("stale", "data"),
        send(HTXF_MAGIC_HEX + "{reference}" + STALE_TAIL_HEX, "stale"),
        eof("stale"),
        close("stale"),
    ]


def read_reference_eof() -> Action:
    """Plan the wait for the server to close the downloading connection.

    Returns
    -------
    native_plan.Action
        The ``read_eof`` action.
    """
    return {"op": "read_eof", "connection": "reference", "timeout": READ_SECONDS}


def download_case(name: str, prefix_size: int) -> Case:
    """Plan one download variant.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = session("a")
    if name == "nonowner":
        steps += session("b")
    steps += [*download_request(), *attach("reference"), *finish_variant(name)]
    steps += cancel("a", OWNER_CANCEL_ID, "reference")
    steps += [read_reference_eof(), close("reference")]
    steps += cancel("a", DUPLICATE_CANCEL_ID, "reference")
    steps += stale_attachment()
    if name == "nonowner":
        steps += [close("b")]
    steps += [close("a")]
    return (
        steps,
        {"kind": "cleanup-download", "variant": name, "prefix_size": prefix_size},
    )


def downloads() -> Cases:
    """Plan the nine download variants.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The cases keyed ``cleanup-`` and the variant name.
    """
    variants = (
        [("baseline", 0), ("nonowner", 0)]
        + [(f"immediate-{i}", 0) for i in range(1, 4)]
        + [(f"partial-{i}", PARTIAL_PREFIX) for i in range(1, 4)]
    )
    return {
        "cleanup-" + name: download_case(name, prefix_size)
        for name, prefix_size in variants
    }
