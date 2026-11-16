"""Prepare HTXF field, collection, reference-use and attachment observations."""

from native_htxf_banners import banners
from native_htxf_steps import (
    FOLDER_SELECTORS,
    FOLLOWUP_ID,
    PUMP_ID,
    READ_SECONDS,
    REQUEST_ID,
    RESERVED_ANY,
    SELECTOR_ANY,
    SIZE_ANY,
    SIZE_BYTES,
    UPLOAD_SELECTOR_PADDING,
    Cases,
    attach,
    data,
    header,
    low_session,
    quiet,
    request,
)
from native_plan import (
    close,
    eof,
    packet,
    payload,
    read,
    send,
)
from native_queue_cases import Case, cancel, pump, session
from native_transfer_cases import file_stream
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    TYPE_DOWNLOAD_FILE,
    TYPE_DOWNLOAD_FOLDER,
    TYPE_GET_FILE_INFO,
    TYPE_UPLOAD_FILE,
)

# prepare_native_cases and verify_native_htxf import htxf; the other planners
# below are kept because the original module defined them publicly.
__all__ = [
    "attach",
    "banners",
    "collections",
    "data",
    "header",
    "htxf",
    "low_session",
    "quiet",
    "request",
]


def sized_download() -> Case:
    """Plan a file download whose header carries unusual words.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [
        *session("a"),
        *request(TYPE_DOWNLOAD_FILE),
        *attach("download", selector=SELECTOR_ANY, size=SIZE_ANY, reserved=0xABCD),
        {
            "op": "read",
            "connection": "download",
            "size_from": "size",
            "timeout": READ_SECONDS,
        },
        quiet("download"),
        *cancel("a", FOLLOWUP_ID, "ref"),
        eof("download"),
        close("download"),
        close("a"),
    ]
    return steps, {"kind": "ordinary-download"}


def wrong_selector_case(selector: int) -> Case:
    """Plan a folder download attached with a selector that is not the folder's.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [
        *session("a"),
        *request(TYPE_DOWNLOAD_FOLDER),
        *attach("wrong", selector=selector),
        eof("wrong"),
        close("wrong"),
        close("a"),
    ]
    return steps, {"kind": "folder-wrong-selector", "selector": selector}


def upload_case(selector: int) -> Case:
    """Plan an ordinary upload whose header carries a selector word.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    filename = f"m-htxf-u{selector}".encode()
    raw = b"header-routing-" + str(selector).encode()
    body = file_stream(raw, b"")
    advertised = len(body) + (UPLOAD_SELECTOR_PADDING if selector == 0 else 0)
    fields = [
        (FIELD_FILE_NAME, filename),
        (FIELD_TRANSFER_SIZE, advertised.to_bytes(SIZE_BYTES, "big")),
    ]
    steps = [
        *session("a"),
        send(packet(TYPE_UPLOAD_FILE, REQUEST_ID, payload(fields)), "a"),
        read(
            "a",
            match_frame={"is_reply": 1, "id": REQUEST_ID},
            save_field={"name": "ref", "id": FIELD_TRANSFER_REFERENCE},
        ),
        *attach("upload", selector=selector, size=len(body), reserved=RESERVED_ANY),
        send(body.hex(), "upload"),
        eof("upload"),
        close("upload"),
        send(
            packet(
                TYPE_GET_FILE_INFO, FOLLOWUP_ID, payload([(FIELD_FILE_NAME, filename)])
            ),
            "a",
        ),
        read("a", match_frame={"is_reply": 1, "id": FOLLOWUP_ID}),
        close("a"),
    ]
    return steps, {
        "kind": "ordinary-upload",
        "selector": selector,
        "filename_hex": filename.hex(),
        "data_hex": raw.hex(),
        "body_hex": body.hex(),
        "request_size": advertised,
    }


def download_case(*, gone: bool) -> tuple[str, Case]:
    """Plan a selector-0 download with a low-privilege session beside it.

    Returns
    -------
    tuple[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The case name and its steps and expectation.
    """
    steps = [*session("a"), *low_session(), *request(TYPE_DOWNLOAD_FILE)]
    if gone:
        steps += [close("a"), *pump("b", PUMP_ID)]
    steps += attach("download", selector=0)
    if gone:
        steps += [eof("download"), close("download"), close("b")]
    else:
        steps += [
            {"op": "read", "connection": "download", "size_from": "size"},
            quiet("download"),
            *cancel("a", FOLLOWUP_ID, "ref"),
            eof("download"),
            close("download"),
            close("a"),
            *pump("b", PUMP_ID),
            close("b"),
        ]
    name = "download-owner-gone" if gone else "download-separate-low-privilege-session"
    return name, (steps, {"kind": name})


def collections() -> Cases:
    """Plan the file, folder and upload observations.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The cases, in the order that the plans have always had.
    """
    cases = {"download-size-reserved-selector-ffff": sized_download()}
    for selector in FOLDER_SELECTORS:
        cases[f"folder-download-wrong-selector-{selector}"] = wrong_selector_case(
            selector
        )
    for selector in FOLDER_SELECTORS:
        cases[f"upload-nonfolder-selector-{selector}"] = upload_case(selector)
    for gone in [False, True]:
        name, case = download_case(gone=gone)
        cases[name] = case
    return cases


def htxf() -> Cases:
    """Plan every HTXF observation.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The banner cases and then the collection cases.
    """
    return banners() | collections()
