"""Check the folder downloads: the empty folder, the traversal and each file."""

from native_filp import decode
from native_folder_cases import FILES, ORDER
from native_folder_stream import download
from native_wire_names import (
    FIELD_ITEM_COUNT,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
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
from verify_native_forks import check_metadata, fields

# The aggregate size of every folder download except the directory-only one.
FULL_FOLDER_BYTES = 652


def check_empty_download(report: Report, values: dict[int, bytes]) -> Report:
    """Check that an empty folder allocated no transfer and opened no data stream.

    Returns
    -------
    dict[str, typing.Any]
        The empty traversal.
    """
    require(
        set(values) == {FIELD_TRANSFER_SIZE, FIELD_ITEM_COUNT}
        and values[FIELD_TRANSFER_SIZE] == b"\0\0"
        and values[FIELD_ITEM_COUNT] == b"\0\0",
        "Empty folder allocated a transfer",
    )
    require(set(report["streams"]) == {"a"}, "Empty folder opened a data connection")
    return {"items": [], "aggregate_bytes": 0, "item_count": 0}


def check_traversal(name: str, items: list[Report]) -> None:
    """Check the order, the paths and the descriptor words of the traversal."""
    expected_order = (
        [(True, (b"only",))] if name == "folder-download-dir-only" else ORDER
    )
    require(
        [(i["directory"], i["path"]) for i in items] == expected_order,
        "Folder traversal order/path differs",
    )
    require(
        all(not any(i["words"]) for i in items),
        "Native descriptor component word changed",
    )


def check_download_file(name: str, item: Report) -> None:
    """Check the choice, resume offsets and fork bytes of one downloaded file."""
    path = item["path"]
    should_skip = name == "folder-download-skip-all" or (
        name == "folder-download-mixed" and path == (b"alpha",)
    )
    if should_skip:
        require(
            item["action"] == "skip" and "body" not in item,
            "Skipped file delivered a body",
        )
        return
    expected_data, expected_resource = FILES[path]
    resume = name == "folder-download-resume" or (
        name == "folder-download-mixed" and path == (b"inner", b"leaf")
    )
    require(
        item["action"] == ("resume" if resume else "fresh"),
        "Folder file choice differs",
    )
    if resume:
        offsets = [
            (b"DATA", 0 if path == (b"zero",) else 3),
            (b"MACR", 0 if path == (b"zero",) else 4),
        ]
        require(item["rflt"] == offsets, "Folder download resume offsets differ")
        expected_data, expected_resource = (
            expected_data[offsets[0][1] :],
            expected_resource[offsets[1][1] :],
        )
    forks = decode(item["body"])
    require(
        forks["DATA"] == expected_data and forks["MACR"] == expected_resource,
        "Folder download fork bytes differ",
    )
    check_metadata(forks["INFO"], path[-1], uploaded=False)


def check_download(name: str, report: Report, packets: Connections) -> Report:
    """Check one folder download against its descriptors, choices and bytes.

    Returns
    -------
    dict[str, typing.Any]
        The items, the aggregate and count, the file bytes and the ignored controls.
    """
    values = fields(response(report))
    if name == "folder-download-empty":
        return check_empty_download(report, values)
    require(
        len(values[FIELD_TRANSFER_REFERENCE]) == REFERENCE_BYTES
        and int.from_bytes(values[FIELD_TRANSFER_REFERENCE], "big") & ODD_REFERENCE_MASK
        != 0,
        "Folder download reference differs",
    )
    sent, received = folder_streams(report)
    require(
        sent[4:8] == values[FIELD_TRANSFER_REFERENCE], "Folder HTXF reference differs"
    )
    parsed = download(sent, received)
    items = parsed["items"]
    check_traversal(name, items)
    count = int.from_bytes(values[FIELD_ITEM_COUNT], "big")
    size = int.from_bytes(values[FIELD_TRANSFER_SIZE], "big")
    require(
        count == len(items)
        and size == (0 if name == "folder-download-dir-only" else FULL_FOLDER_BYTES),
        "Folder aggregate/count differs",
    )
    require(
        packets["folder"]["guest_server_initiated_close"],
        "Folder traversal did not close natively",
    )
    for item in items:
        if not item["directory"]:
            check_download_file(name, item)
    require(
        parsed["ignored"]
        == (
            [{"state": 0, "control": 0}, {"state": 1, "control": 0}]
            if name == "folder-download-unknown-control"
            else []
        ),
        "Unexpected folder control handling",
    )
    return {
        "items": summarize(items),
        "aggregate_bytes": size,
        "item_count": count,
        "file_stream_bytes": sum(len(i.get("body", b"")) for i in items),
        "ignored": parsed["ignored"],
    }
