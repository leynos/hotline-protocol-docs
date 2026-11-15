"""Prepare empty, partial, resumed and conflicting native folder uploads."""

from native_folder_steps import (
    PARTIAL,
    READ_SECONDS,
    STREAM_LENGTH_BYTES,
    WORD_BYTES,
    Cases,
    descriptor,
    framed_hex,
    path,
    silence_folder,
    upload_start,
    word,
)
from native_plan import close, connect, eof, packet, payload, read, send
from native_queue_cases import session
from native_resume_cases import rflt
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FOLDER_CONTROL_FRESH,
    FOLDER_CONTROL_NEXT,
    FOLDER_CONTROL_RESUME,
    HTXF_MAGIC_HEX,
    TYPE_GET_FILE_INFO,
    TYPE_UPLOAD_FILE,
)

FLUSH_REQUEST_ID = 10  # the auxiliary upload's request identifier
PARTIAL_CUT_BYTES = 312  # bytes withheld from the end of the second partial body
PARTIAL_PAUSE_SECONDS = 2  # pause before the partial-seed file-info requests
PARTIAL_DATA_BYTES = 13  # data-fork bytes held by the partial upload
PARTIAL_RESOURCE_BYTES = 5  # resource-fork bytes held by the partial upload


def empty_uploads() -> Cases:
    """Plan the zero-item upload and the upload whose last item is a directory.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The zero-item and directory-last cases, by name.
    """
    steps = upload_start(b"mothra-folder-dirlast", 1, 0)
    steps += [
        send(descriptor((b"only",), directory=True).hex(), "folder"),
        word(FOLDER_CONTROL_NEXT),
        eof("folder"),
        close("folder"),
        close("a"),
    ]
    return {
        "folder-upload-zero-items": (
            upload_start(b"mothra-folder-empty", 0, 0),
            {"kind": "folder-upload-zero-items"},
        ),
        "folder-upload-directory-last": (
            steps,
            {"kind": "folder-upload-directory-last"},
        ),
    }


def catalogue_flush() -> Cases:
    """Finalize an independent file; INFO restoration invokes native FlushVol.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one catalogue-flush case.
    """
    body = file_stream(b"", b"")
    steps = [
        *session("a"),
        send(
            packet(
                TYPE_UPLOAD_FILE,
                FLUSH_REQUEST_ID,
                payload([
                    (FIELD_FILE_NAME, b"mothra-folder-flush"),
                    (FIELD_TRANSFER_SIZE, len(body).to_bytes(4, "big")),
                ]),
            ),
            "a",
        ),
        read(
            "a",
            match_frame={"is_reply": 1, "id": FLUSH_REQUEST_ID},
            save_field={"name": "reference", "id": FIELD_TRANSFER_REFERENCE},
        ),
        connect("upload", "data"),
        send(
            HTXF_MAGIC_HEX
            + "{reference}"
            + len(body).to_bytes(4, "big").hex()
            + "00000000"
            + body.hex(),
            "upload",
        ),
        eof("upload"),
        close("upload"),
        close("a"),
    ]
    return {
        "folder-catalogue-flush": (
            steps,
            {
                "kind": "folder-catalogue-flush",
                "scope": (
                    "Auxiliary finalization outside tested folder roots; "
                    "native FlushVol return is unchecked"
                ),
            },
        )
    }


def partial_seed() -> Cases:
    """Plan a partial upload of three items, with two file-info requests after it.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one partial-seed case.
    """
    body = file_stream(b"data-fork\r\n\x00\xff", resource_fork())
    steps = upload_start(PARTIAL, 3, 2 * len(body))
    steps += [
        send(descriptor((b"alpha",), directory=False).hex(), "folder"),
        word(FOLDER_CONTROL_FRESH),
        send(framed_hex(body), "folder"),
        word(FOLDER_CONTROL_NEXT),
    ]
    steps += [
        send(descriptor((b"part",), directory=False).hex(), "folder"),
        word(FOLDER_CONTROL_FRESH),
        send(
            (
                len(body).to_bytes(STREAM_LENGTH_BYTES, "big")
                + body[:-PARTIAL_CUT_BYTES]
            ).hex(),
            "folder",
        ),
    ]
    steps += [
        silence_folder(),
        close("folder"),
        {"op": "pause", "seconds": PARTIAL_PAUSE_SECONDS},
    ]
    for identifier, name in [(11, b"alpha"), (12, b"part")]:
        steps += [
            send(
                packet(
                    TYPE_GET_FILE_INFO,
                    identifier,
                    payload([
                        (FIELD_FILE_NAME, name),
                        (FIELD_FILE_PATH, path((PARTIAL,))),
                    ]),
                ),
                "a",
            ),
            read("a", match_frame={"is_reply": 1, "id": identifier}),
        ]
    steps += [close("a")]
    return {
        "folder-upload-partial-seed": (
            steps,
            {
                "kind": "folder-upload-partial-seed",
                "declared_items": 3,
                "completed_items": 1,
                "partial_data": PARTIAL_DATA_BYTES,
                "partial_resource": PARTIAL_RESOURCE_BYTES,
            },
        )
    }


def resumed_uploads() -> Cases:
    """Plan a resumed partial upload and the two conflicting resumed uploads.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The resume case and the completed-skip and directory-conflict cases.
    """
    body = file_stream(b"", resource_fork()[5:])
    steps = upload_start(PARTIAL, 3, 660, resume=True)
    steps += [
        send(descriptor((b"alpha",), directory=False).hex(), "folder"),
        word(FOLDER_CONTROL_NEXT),
    ]
    value = rflt([(b"DATA", PARTIAL_DATA_BYTES), (b"MACR", PARTIAL_RESOURCE_BYTES)])
    steps += [
        send(descriptor((b"part",), directory=False).hex(), "folder"),
        word(FOLDER_CONTROL_RESUME),
        {
            "op": "read",
            "connection": "folder",
            "size": WORD_BYTES,
            "expect_hex": len(value).to_bytes(WORD_BYTES, "big").hex(),
            "timeout": READ_SECONDS,
        },
        {
            "op": "read",
            "connection": "folder",
            "size": len(value),
            "expect_hex": value.hex(),
            "timeout": READ_SECONDS,
        },
    ]
    steps += [send(framed_hex(body), "folder"), word(FOLDER_CONTROL_NEXT)]
    steps += [
        send(descriptor((b"finish",), directory=True).hex(), "folder"),
        word(FOLDER_CONTROL_NEXT),
        eof("folder"),
        close("folder"),
        close("a"),
    ]
    cases: Cases = {"folder-upload-resume": (steps, {"kind": "folder-upload-resume"})}
    for name, directory in [("completed-skip", False), ("directory-conflict", True)]:
        steps = upload_start(PARTIAL, 1, 330, resume=True)
        steps += [
            send(descriptor((b"alpha",), directory).hex(), "folder"),
            word(FOLDER_CONTROL_NEXT),
            eof("folder"),
            close("folder"),
            close("a"),
        ]
        cases["folder-upload-" + name] = (steps, {"kind": "folder-upload-" + name})
    return cases
