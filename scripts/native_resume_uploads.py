"""Prepare interrupted native uploads and their resume negotiation."""

from native_plan import (
    QUIET_WINDOW_SECONDS,
    Action,
    close,
    connect,
    eof,
    login,
    packet,
    payload,
    read,
    send,
)
from native_resume_rflt import (
    DOWNLOAD_ID,
    FOLLOWUP_ID,
    FORK_DATA,
    FORK_NAME,
    HTXF_DOWNLOAD_TAIL,
    HTXF_UPLOAD_TAIL,
    MACR_BYTES,
    MACR_RETAINED_BYTES,
    MISSING_NAME,
    READ_SECONDS,
    REQUEST_ID,
    RESUME_INCONSISTENT_NAME,
    RESUME_PARTIAL_NAME,
    SEED_PAUSE_SECONDS,
    SIZE_BYTES,
    Case,
    rflt,
)
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_RESUME_DATA,
    FIELD_TRANSFER_OPTION,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    RESUME_OPTION,
    TYPE_DOWNLOAD_FILE,
    TYPE_GET_FILE_INFO,
    TYPE_UPLOAD_FILE,
)


def seed_upload(filename: bytes) -> Case:
    """Leave DATA13/MACR5 under the native incomplete-file type.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and expectation of the case.
    """
    body = file_stream(FORK_DATA, resource_fork())
    prefix = body[: -(MACR_BYTES - MACR_RETAINED_BYTES)]
    size = len(body).to_bytes(SIZE_BYTES, "big")
    request = payload([(FIELD_FILE_NAME, filename), (FIELD_TRANSFER_SIZE, size)])
    steps = [
        *login(),
        send(packet(TYPE_UPLOAD_FILE, REQUEST_ID, request)),
        read(
            match_frame={"is_reply": 1, "id": REQUEST_ID},
            save_field={"name": "reference", "id": FIELD_TRANSFER_REFERENCE},
        ),
        connect("upload", "data"),
        send(
            HTXF_MAGIC_HEX
            + "{reference}"
            + size.hex()
            + HTXF_UPLOAD_TAIL
            + prefix.hex(),
            "upload",
        ),
        {
            "op": "expect_quiet",
            "connection": "upload",
            "timeout": QUIET_WINDOW_SECONDS,
        },
        close("upload"),
        {"op": "pause", "seconds": SEED_PAUSE_SECONDS},
        send(
            packet(
                TYPE_GET_FILE_INFO, FOLLOWUP_ID, payload([(FIELD_FILE_NAME, filename)])
            )
        ),
        read(match_frame={"is_reply": 1, "id": FOLLOWUP_ID}),
        close(),
    ]
    return steps, {
        "kind": "upload-prefix",
        "name_hex": filename.hex(),
        "prefix_hex": prefix.hex(),
        "full_stream_hex": body.hex(),
    }


def resume_probe(target_name: bytes, size: bytes) -> Case:
    """Plan an upload request that asks to resume, and read only its reply.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and expectation of the case.
    """
    fields = [
        (FIELD_FILE_NAME, target_name),
        (FIELD_TRANSFER_OPTION, RESUME_OPTION.to_bytes(2, "big")),
        (FIELD_TRANSFER_SIZE, size),
    ]
    steps = [
        *login(),
        send(packet(TYPE_UPLOAD_FILE, REQUEST_ID, payload(fields))),
        read(match_frame={"is_reply": 1, "id": REQUEST_ID}),
        close(),
    ]
    return steps, {"kind": "resume-upload-probe", "name_hex": target_name.hex()}


def upload_probes() -> dict[str, Case]:
    """Seed an interrupted native upload, then inspect resume negotiation.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of the seed and of each probe, by name.
    """
    cases = {"resume-upload-seed": seed_upload(RESUME_PARTIAL_NAME)}
    body = file_stream(FORK_DATA, resource_fork())
    size = len(body).to_bytes(SIZE_BYTES, "big")
    for name, target_name in [
        ("partial", RESUME_PARTIAL_NAME),
        ("missing", MISSING_NAME),
        ("completed", FORK_NAME),
    ]:
        cases["resume-upload-probe-" + name] = resume_probe(target_name, size)
    return cases


def download_back(filename: bytes) -> list[Action]:
    """Plan reading back the file that an upload has completed.

    Returns
    -------
    list[native_plan.Action]
        The download request, its data connection and the sized read.
    """
    return [
        send(
            packet(
                TYPE_DOWNLOAD_FILE, DOWNLOAD_ID, payload([(FIELD_FILE_NAME, filename)])
            )
        ),
        read(
            match_frame={"is_reply": 1, "id": DOWNLOAD_ID},
            save_fields={
                "download_reference": FIELD_TRANSFER_REFERENCE,
                "size": FIELD_TRANSFER_SIZE,
            },
        ),
        connect("download", "data"),
        send(HTXF_MAGIC_HEX + "{download_reference}" + HTXF_DOWNLOAD_TAIL, "download"),
        {
            "op": "read",
            "connection": "download",
            "size_from": "size",
            "timeout": READ_SECONDS,
        },
        {
            "op": "expect_quiet",
            "connection": "download",
            "timeout": QUIET_WINDOW_SECONDS,
        },
        close("download"),
        close(),
    ]


def finish_upload(filename: bytes, *, inconsistent: bool) -> Case:
    """Plan resuming an upload to completion and reading the file back.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and expectation of the case.
    """
    data = FORK_DATA if inconsistent else b""
    resource = (
        resource_fork() if inconsistent else resource_fork()[MACR_RETAINED_BYTES:]
    )
    body = file_stream(data, resource)
    size = len(body).to_bytes(SIZE_BYTES, "big")
    fields = [
        (FIELD_FILE_NAME, filename),
        (FIELD_TRANSFER_OPTION, RESUME_OPTION.to_bytes(2, "big")),
        (FIELD_TRANSFER_SIZE, size),
    ]
    if inconsistent:
        fields.append((FIELD_RESUME_DATA, rflt([(b"DATA", 0), (b"MACR", 0)])))
    steps = [
        *login(),
        send(packet(TYPE_UPLOAD_FILE, REQUEST_ID, payload(fields))),
        read(
            match_frame={"is_reply": 1, "id": REQUEST_ID},
            save_fields={
                "reference": FIELD_TRANSFER_REFERENCE,
                "offsets": FIELD_RESUME_DATA,
            },
        ),
        connect("upload", "data"),
        send(
            HTXF_MAGIC_HEX + "{reference}" + size.hex() + HTXF_UPLOAD_TAIL + body.hex(),
            "upload",
        ),
        eof("upload"),
        close("upload"),
        send(
            packet(
                TYPE_GET_FILE_INFO, FOLLOWUP_ID, payload([(FIELD_FILE_NAME, filename)])
            )
        ),
        read(match_frame={"is_reply": 1, "id": FOLLOWUP_ID}),
        *download_back(filename),
    ]
    return steps, {
        "kind": "resume-upload-completion",
        "name_hex": filename.hex(),
        "inconsistent": inconsistent,
        "stream_hex": body.hex(),
    }


def upload_continuations() -> dict[str, Case]:
    """Plan resuming a consistent and an inconsistent interrupted upload.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by name.
    """
    return {
        "resume-upload-complete": finish_upload(
            RESUME_PARTIAL_NAME, inconsistent=False
        ),
        "resume-upload-inconsistent-seed": seed_upload(RESUME_INCONSISTENT_NAME),
        "resume-upload-inconsistent-complete": finish_upload(
            RESUME_INCONSISTENT_NAME, inconsistent=True
        ),
    }
