"""Check the folder uploads: the server's item choices, bytes and completion."""

from native_filp import decode
from native_folder_cases import FILES
from native_folder_stream import upload
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    FIELD_FILE_SIZE,
    FIELD_FILE_TYPE,
    FIELD_TRANSFER_REFERENCE,
    FOLDER_CONTROL_NEXT,
    FOLDER_CONTROL_RESUME,
)
from verify_native_core import require
from verify_native_folder_support import (
    ODD_REFERENCE_MASK,
    REFERENCE_BYTES,
    Connections,
    Report,
    folder_streams,
    response,
    summarize,
)
from verify_native_forks import check_file_info, check_metadata, fields

# Bytes of the partial "alpha" stream that the interrupted upload delivered, and
# the bytes of it that were cut off (the final 312).
PARTIAL_STREAM_BYTES = 509
PARTIAL_OMITTED_BYTES = 312
# Offsets that the resume negotiation names: the DATA fork and the MACR fork.
UPLOAD_RESUME_DATA_OFFSET = 13
UPLOAD_RESUME_RESOURCE_OFFSET = 5
# The logical size that the file-info check of "alpha" was given.
ALPHA_LOGICAL_SIZE = 330
# The frame IDs of the two file-info requests of the partial case.
FILE_INFO_ALPHA_ID = 11
FILE_INFO_PART_ID = 12
# The raw size that the file-info reply of "part" must carry.
PARTIAL_FILE_INFO_SIZE = 18

# The expected item paths, directory flags and control words of each case.
UPLOAD_PATHS: dict[str, list[tuple[bytes, ...]]] = {
    "folder-upload-fresh": [
        (b"empty",),
        (b"inner",),
        (b"alpha",),
        (b"zero",),
        (b"inner", b"leaf"),
    ],
    "folder-upload-directory-last": [(b"only",)],
    "folder-upload-partial-seed": [(b"alpha",), (b"part",)],
    "folder-upload-resume": [(b"alpha",), (b"part",), (b"finish",)],
    "folder-upload-completed-skip": [(b"alpha",)],
    "folder-upload-directory-conflict": [(b"alpha",)],
}
UPLOAD_DIRECTORIES: dict[str, list[bool]] = {
    "folder-upload-fresh": [True, True, False, False, False],
    "folder-upload-directory-last": [True],
    "folder-upload-partial-seed": [False, False],
    "folder-upload-resume": [False, False, True],
    "folder-upload-completed-skip": [False],
    "folder-upload-directory-conflict": [True],
}
UPLOAD_CONTROLS: dict[str, list[int]] = {
    "folder-upload-fresh": [3, 3, 1, 1, 1],
    "folder-upload-directory-last": [3],
    "folder-upload-partial-seed": [1, 1],
    "folder-upload-resume": [3, 2, 3],
    "folder-upload-completed-skip": [3],
    "folder-upload-directory-conflict": [3],
}


def read_upload(report: Report, values: dict[int, bytes]) -> Report:
    """Check the reference of the upload ACK and parse the folder stream.

    Returns
    -------
    dict[str, typing.Any]
        The parsed items and the count of completed items.
    """
    require(
        set(values) == {FIELD_TRANSFER_REFERENCE}
        and len(values[FIELD_TRANSFER_REFERENCE]) == REFERENCE_BYTES
        and not int.from_bytes(values[FIELD_TRANSFER_REFERENCE], "big")
        & ODD_REFERENCE_MASK,
        "Folder upload ACK differs",
    )
    sent, received = folder_streams(report)
    require(
        sent[4:8] == values[FIELD_TRANSFER_REFERENCE], "Folder upload reference differs"
    )
    return upload(sent, received)


def check_upload_layout(name: str, items: list[Report]) -> None:
    """Check the paths, directory flags and control words of the items."""
    expected_paths = UPLOAD_PATHS[name]
    require([i["path"] for i in items] == expected_paths, "Folder upload paths differ")
    expected_directories = UPLOAD_DIRECTORIES[name]
    require(
        [i["flags"] for i in items] == [int(v) for v in expected_directories],
        "Folder upload item flags differ",
    )
    expected_controls = UPLOAD_CONTROLS[name]
    require(
        [i["control"] for i in items] == expected_controls,
        "Folder upload choice sequence differs",
    )


def check_upload_item(name: str, item: Report, *, has_next: bool) -> None:
    """Check the bytes, negotiation and next control of one uploaded item."""
    require(not any(item["words"]), "Unexpected upload component word")
    if "body" not in item:
        return
    if not item["complete"]:
        require(
            name == "folder-upload-partial-seed"
            and item["stream_size"] == PARTIAL_STREAM_BYTES
            and item["body"] == file_stream(*FILES[b"alpha",])[:-PARTIAL_OMITTED_BYTES],
            "Partial folder stream differs",
        )
        return
    forks = decode(item["body"])
    expected = (
        FILES[item["path"]] if name == "folder-upload-fresh" else FILES[b"alpha",]
    )
    if item["control"] == FOLDER_CONTROL_RESUME:
        require(
            item["rflt"]
            == [
                (b"DATA", UPLOAD_RESUME_DATA_OFFSET),
                (b"MACR", UPLOAD_RESUME_RESOURCE_OFFSET),
            ],
            "Folder upload resume negotiation differs",
        )
        expected = (b"", resource_fork()[UPLOAD_RESUME_RESOURCE_OFFSET:])
    require(
        (forks["DATA"], forks["MACR"]) == expected, "Folder upload fork bytes differ"
    )
    check_metadata(forks["INFO"], item["path"][-1], uploaded=True)
    require(item["next_ready"] == has_next, "File-ending next-control differs")


def check_upload_completion(
    name: str, report: Report, packets: Connections, parsed: Report
) -> None:
    """Check the close and the completed count, and the partial file-info state."""
    partial = name == "folder-upload-partial-seed"
    require(
        packets["folder"]["guest_server_initiated_close"] != partial,
        "Folder completion/interruption close differs",
    )
    if partial:
        require(parsed["completed"] == 1, "Partial item was counted complete")
        check_file_info(
            response(report, FILE_INFO_ALPHA_ID), b"alpha", ALPHA_LOGICAL_SIZE
        )
        info = fields(response(report, FILE_INFO_PART_ID))
        require(
            info[FIELD_FILE_TYPE] == b"HTft"
            and int.from_bytes(info[FIELD_FILE_SIZE], "big") == PARTIAL_FILE_INFO_SIZE,
            "Partial file-info state differs",
        )
    else:
        require(
            parsed["completed"] == len(parsed["items"]),
            "Folder processed-item count differs",
        )


def check_upload(name: str, report: Report, packets: Connections) -> Report:
    """Check one folder upload against the server's choices and the bytes sent.

    Returns
    -------
    dict[str, typing.Any]
        The items, the completed count and the kind of the final item.
    """
    values = fields(response(report))
    if name == "folder-upload-zero-items":
        require(
            not values and set(report["streams"]) == {"a"},
            "Zero-item upload allocated a reference",
        )
        return {"items": [], "completed_items": 0}
    parsed = read_upload(report, values)
    items = parsed["items"]
    check_upload_layout(name, items)
    for index, item in enumerate(items):
        check_upload_item(name, item, has_next=index < len(items) - 1)
    check_upload_completion(name, report, packets, parsed)
    return {
        "items": summarize(items),
        "completed_items": parsed["completed"],
        "final_item_kind": "directory-or-skip"
        if items[-1]["control"] == FOLDER_CONTROL_NEXT
        else "file",
    }
