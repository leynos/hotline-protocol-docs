"""Prepare bounded RFLT resume observations with complete entry records."""

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
    DATA_BYTES,
    FOLLOWUP_ID,
    FORK_NAME,
    HTXF_DOWNLOAD_TAIL,
    MACR_BYTES,
    PAUSE_SECONDS,
    READ_SECONDS,
    REQUEST_ID,
    RFLT_UPGRADE_VERSION,
    UINT32_MAX,
    Case,
    Entries,
    rflt,
)

# verify_native_resume, prepare_native_cases and native_folder_cases import
# these names from this module, whose planners they belong to.
from native_resume_uploads import upload_continuations, upload_probes
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_RESUME_DATA,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    RFLT_MAGIC,
    RFLT_MIN_BYTES,
    RFLT_VERSION,
    TYPE_DOWNLOAD_FILE,
    TYPE_EMPTY_ACK,
)

__all__ = ["downloads", "rflt", "upload_continuations", "upload_probes"]

VARIANTS: dict[str, Entries] = {
    "zero-entries": [],
    "data-zero": [(b"DATA", 0)],
    "data-inside": [(b"DATA", 3)],
    "resource-inside": [(b"MACR", 4)],
    "both-inside": [(b"DATA", 3), (b"MACR", 4)],
    "both-eof": [(b"DATA", DATA_BYTES), (b"MACR", MACR_BYTES)],
    "both-beyond": [(b"DATA", DATA_BYTES + 1), (b"MACR", MACR_BYTES + 1)],
    "both-uint32-max": [(b"DATA", UINT32_MAX), (b"MACR", UINT32_MAX)],
    "unknown-tag": [(b"XXXX", 123)],
    "duplicate-data-3-4": [(b"DATA", 3), (b"DATA", 4)],
    "duplicate-data-4-3": [(b"DATA", 4), (b"DATA", 3)],
    "duplicate-data-beyond-inside": [(b"DATA", DATA_BYTES + 1), (b"DATA", 1)],
    "duplicate-resource-3-4": [(b"MACR", 3), (b"MACR", 4)],
}
OVERFLOW_VARIANT = "both-uint32-max"


def download_stream(variant: str) -> list[Action]:
    """Plan the data connection that follows a resume download request.

    Returns
    -------
    list[native_plan.Action]
        The connect, the greeting, and either the end of stream, for the offset
        that overflows, or the sized read and a quiet window.
    """
    steps: list[Action] = [
        connect("download", "data"),
        send(HTXF_MAGIC_HEX + "{reference}" + HTXF_DOWNLOAD_TAIL, "download"),
    ]
    if variant == OVERFLOW_VARIANT:
        return [*steps, eof("download")]
    return [
        *steps,
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
    ]


def resume_download(name: str, entries: Entries) -> Case:
    """Plan a download that supplies a resume descriptor.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and expectation of the case.
    """
    encoded = rflt(entries)
    fields = [(FIELD_FILE_NAME, FORK_NAME), (FIELD_RESUME_DATA, encoded)]
    steps = [
        *login(),
        send(packet(TYPE_DOWNLOAD_FILE, REQUEST_ID, payload(fields))),
        read(
            match_frame={"is_reply": 1, "id": REQUEST_ID},
            save_fields={
                "reference": FIELD_TRANSFER_REFERENCE,
                "size": FIELD_TRANSFER_SIZE,
            },
        ),
        *download_stream(name),
        close("download"),
        close(),
    ]
    return steps, {
        "kind": "resume-data-error" if name == OVERFLOW_VARIANT else "resume-download",
        "name_hex": FORK_NAME.hex(),
        "rflt_hex": encoded.hex(),
        "entries": [{"tag": tag.decode(), "offset": offset} for tag, offset in entries],
    }


def rejected_download(encoded: bytes) -> Case:
    """Plan a download whose descriptor is refused, so that no reply comes.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and expectation of the case.
    """
    fields = [(FIELD_FILE_NAME, FORK_NAME), (FIELD_RESUME_DATA, encoded)]
    steps = [
        *login(),
        send(packet(TYPE_DOWNLOAD_FILE, REQUEST_ID, payload(fields))),
        {"op": "pause", "seconds": PAUSE_SECONDS},
        send(packet(TYPE_EMPTY_ACK, FOLLOWUP_ID)),
        read(match_frame={"is_reply": 1, "id": FOLLOWUP_ID}),
        close(),
    ]
    return steps, {"kind": "resume-no-reply", "rflt_hex": encoded.hex()}


def downloads() -> dict[str, Case]:
    """Plan the resume downloads, then those with an unusable descriptor.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The steps and expectation of each case, by name.
    """
    cases = {
        "resume-download-" + name: resume_download(name, entries)
        for name, entries in VARIANTS.items()
    }
    valid = rflt([])
    for name, encoded in {
        "short-41": valid[: RFLT_MIN_BYTES - 1],
        "wrong-magic": b"XXXX" + valid[len(RFLT_MAGIC) :],
        "wrong-version": (
            valid[: len(RFLT_MAGIC)]
            + RFLT_UPGRADE_VERSION
            + valid[len(RFLT_MAGIC + RFLT_VERSION) :]
        ),
    }.items():
        cases["resume-download-" + name] = rejected_download(encoded)
    return cases
