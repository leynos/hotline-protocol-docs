"""Check each banner format capture and the native files that hold the formats.

A format case uploads a file with a given Finder type and checks the 122 tag, the
212 size and the raw bytes that the banner connection delivers.
"""

import json
import typing as typ

from native_banner_cases import URL
from native_banner_formats import FORMATS, content
from native_wire_names import (
    FIELD_BANNER_LINK,
    FIELD_BANNER_TYPE,
    FIELD_NAME,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    FIELD_VERSION,
    FRAME_HEADER_BYTES,
    FRAME_SIZE_START,
    HANDSHAKE_REQUEST_HEX,
    HTXF_MAGIC_HEX,
    TYPE_ACCEPT_AGREEMENT,
    TYPE_BANNER_METADATA,
    TYPE_LOGIN,
)
from protocol_capture import decode_frame
from verify_native_banners import fields
from verify_native_core import require

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

HANDSHAKE_BYTES = len(bytes.fromhex(HANDSHAKE_REQUEST_HEX))
REFERENCE_BYTES = 4
OWNER_REQUEST = 10  # the 212 request of every case
DELAYED_VERSION = b"\0\xbe"  # reported version 190, as the delayed login sends
# The data connection greets with `HTXF`, the reference, a zero size word, the
# banner selector 2 and a reserved word (transfer-contracts.md, "HTXF").
HTXF_BANNER_TAIL_HEX = "0000000000020000"
NO_FINDER_TYPE = bytes(4)
ZERO_TYPE_STAT = "0000"  # how the stat listing writes an all-zero Finder type
NATIVE_SOURCES = ["native-format-files", "native-text-file", "native-empty-file"]


def requests(report: Report, connection: str) -> list[Report]:
    """Decode the requests that a connection sent after its handshake.

    Returns
    -------
    list[dict[str, typing.Any]]
        One decoded frame for each request, in order.
    """
    data = bytes.fromhex(report["streams"][connection]["sent_hex"])
    require(
        data[:HANDSHAKE_BYTES] == bytes.fromhex(HANDSHAKE_REQUEST_HEX),
        "Wrong format control handshake",
    )
    data = data[HANDSHAKE_BYTES:]
    result = []
    while data:
        require(len(data) >= FRAME_HEADER_BYTES, "Truncated format request")
        size = FRAME_HEADER_BYTES + int.from_bytes(
            data[FRAME_SIZE_START:FRAME_HEADER_BYTES], "big"
        )
        require(len(data) >= size, "Truncated format payload")
        result.append(decode_frame(data[:size]))
        data = data[size:]
    return result


def banners(report: Report, connection: str) -> list[Report]:
    """Select the 122 notifications that a connection received.

    Returns
    -------
    list[dict[str, typing.Any]]
        The notification frames.
    """
    return [
        f
        for f in report["frames"]
        if f["connection"] == connection
        and f["type"] == TYPE_BANNER_METADATA
        and not f["is_reply"]
    ]


def banner_ack(report: Report) -> tuple[bytes, int]:
    """Read the 212 ACK of the main connection.

    Returns
    -------
    tuple[bytes, int]
        The banner reference and the advertised size.
    """
    acks = [
        f
        for f in report["frames"]
        if f["connection"] == "main" and f["is_reply"] and f["id"] == OWNER_REQUEST
    ]
    require(len(acks) == 1 and acks[0]["error"] == 0, "Missing banner212 ACK")
    values = fields(acks[0])
    require(
        set(values) == {FIELD_TRANSFER_REFERENCE, FIELD_TRANSFER_SIZE},
        "Banner212 field inventory differs",
    )
    ref = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(ref) == REFERENCE_BYTES and int.from_bytes(ref, "big") & 1 == 1,
        "Banner reference differs",
    )
    return ref, int.from_bytes(values[FIELD_TRANSFER_SIZE], "big")


def check_format(name: str, report: Report) -> Report:
    """Check one format case: its input, 122 tag, advertised size and bytes.

    Returns
    -------
    dict[str, typing.Any]
        The format, its Finder type and tag, and the byte counts.
    """
    require(report["status"] == "completed", name + ": incomplete format capture")
    input_frames = requests(report, "main")
    require(
        input_frames[0]["type"] == TYPE_LOGIN
        and fields(input_frames[0])[FIELD_VERSION] == DELAYED_VERSION
        and FIELD_NAME not in fields(input_frames[0])
        and any(f["type"] == TYPE_ACCEPT_AGREEMENT for f in input_frames),
        name + ": delayed input differs",
    )
    filename, finder, tag, _ = FORMATS[name]
    notes = banners(report, "main")
    require(len(notes) == int(tag is not None), name + ": metadata eligibility differs")
    if tag is not None:
        require(
            fields(notes[0]) == {FIELD_BANNER_TYPE: tag, FIELD_BANNER_LINK: URL},
            name + ": advertised type/link differs",
        )
    reference, size = banner_ack(report)
    expected = content(name)
    if finder == b"TEXT":
        expected = expected.replace(b"\r\n", b"\r")
    require(size == len(expected), name + ": advertised byte count differs")
    value = report["streams"]["banner"]
    require(
        value["sent_hex"] == HTXF_MAGIC_HEX + reference.hex() + HTXF_BANNER_TAIL_HEX,
        name + ": HTXF differs",
    )
    require(
        bytes.fromhex(value["received_hex"]) == expected, name + ": payload differs"
    )
    require(
        any(
            e["event"] == ("quiet" if expected else "eof")
            and e["connection"] == "banner"
            for e in report["events"]
        ),
        name + ": missing banner end/window observation",
    )
    return {
        "format": name,
        "filename_hex": filename.hex(),
        "finder_hex": finder.hex(),
        "tag_hex": tag.hex() if tag is not None else None,
        "native_file_bytes": len(content(name)),
        "advertised_bytes": size,
        "received_bytes": len(expected),
    }


def native_records(directory: Path) -> list[tuple[Path, Report]]:
    """Gather the extraction records of every native file listing.

    Returns
    -------
    list[tuple[pathlib.Path, dict[str, typing.Any]]]
        Each listing's directory and one of its records.
    """
    records = []
    for source in NATIVE_SOURCES:
        snapshot = json.loads((directory / source / "extraction.json").read_text())
        records.extend((directory / source, record) for record in snapshot["records"])
    return records


def verify_native_files(directory: Path) -> list[Report]:
    """Check that the native filesystem holds each format as uploaded.

    Returns
    -------
    list[dict[str, typing.Any]]
        The path, catalogue entry and data size of each format.
    """
    records = native_records(directory)
    observed = []
    for name, (filename, finder, _, _) in FORMATS.items():
        matches = [
            (source, record)
            for source, record in records
            if record["path"] == "/Hotline19/" + filename.decode()
        ]
        require(len(matches) == 1, name + ": native path not uniquely observed")
        source, record = matches[0]
        prefix = source / record["key"]
        data = record["attributes"]["data"]
        require(
            data["exit_code"] == 0 and data["bytes"] == len(content(name)),
            name + ": native extraction differs",
        )
        require(
            prefix.with_suffix(".data").read_bytes() == content(name),
            name + ": native data fork differs",
        )
        stat = prefix.with_suffix(".stat.txt").read_text()
        shown = ZERO_TYPE_STAT if finder == NO_FINDER_TYPE else finder.hex()
        require(
            ("File type:\t" + shown) in stat and "MOTH" in stat,
            name + ": native Finder type differs",
        )
        observed.append({
            "format": name,
            "path": record["path"],
            "catalog": record["catalog"],
            "data_bytes": data["bytes"],
        })
    return observed
