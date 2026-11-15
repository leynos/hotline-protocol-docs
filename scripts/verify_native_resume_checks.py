"""Check the bytes of each native RFLT resume case against its recorded capture.

Downloads pin the fork ranges that each descriptor selects; uploads pin the
negotiated offsets, the seeded prefix and the bytes of the continuation.
"""

import dataclasses as dc
import typing as typ

from native_filp import decode
from native_resume_cases import rflt
from native_resume_rflt import FORK_DATA as DATA
from native_resume_rflt import MISSING_NAME, RESUME_PARTIAL_NAME
from native_transfer_cases import resource_fork
from native_wire_names import (
    FIELD_ERROR_TEXT,
    FIELD_FILE_SIZE,
    FIELD_FILE_TYPE,
    FIELD_RESUME_DATA,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
)
from verify_native_core import require
from verify_native_forks import check_file_info, check_metadata, fields

type Report = dict[str, typ.Any]

RESOURCE = resource_fork()

# transfer-contracts.md, "Captured RFLT download boundaries" and "Captured upload
# continuation": the logical size, the overhead of an empty-fork stream, and the
# sizes of the seeded interrupted upload.
LOGICAL_BYTES = 330
EMPTY_FORKS_BYTES = 180  # INFO and the three headers, with no DATA or MACR
SEED_STREAM_BYTES = 509
SEED_SENT_BYTES = 197
SEED_LOGICAL_BYTES = 18  # 13 DATA bytes and 5 MACR bytes
SEED_TYPE = b"HTft"  # the native incomplete-file type
DATA_OFFSET = 13
RESOURCE_OFFSET = 5
REQUEST_ID = 10
FOLLOWUP_ID = 11
READBACK_ID = 12
ACK_PAYLOAD_HEX = "0000"
PAUSE_SECONDS = 3
NANOSECONDS_PER_SECOND = 1e9
REFERENCE_BYTES = 4
HTXF_MAGIC = b"HTXF"
HTXF_TAIL = bytes(8)
HTXF_HEADER_BYTES = 16  # magic, reference, size word, selector and reserved word
HTXF_SIZE_START = 8
HTXF_SIZE_END = 12
HTXF_TAIL_START = 12
ERROR_REPLY = 1
FORK_NAME = b"mothra-fork-fixture"


def reply(report: Report, identifier: int) -> Report:
    """Find the one direct reply to a control request.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    selected = [
        f for f in report["frames"] if f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(selected) == 1, "Missing or duplicate control reply")
    require(selected[0]["type"] == 0, "Unexpected direct reply type")
    return selected[0]


def expected_forks(name: str) -> tuple[bytes, bytes]:
    """Pin observed byte ranges, including noncanonical repeated-entry outcomes.

    Returns
    -------
    tuple[bytes, bytes]
        The DATA and MACR bytes that the named descriptor selects.
    """
    return {
        "zero-entries": (DATA, RESOURCE),
        "data-zero": (DATA, RESOURCE),
        "data-inside": (DATA[3:], RESOURCE),
        "resource-inside": (DATA, RESOURCE[4:]),
        "both-inside": (DATA[3:], RESOURCE[4:]),
        "both-eof": (b"", b""),
        "both-beyond": (b"", b""),
        "unknown-tag": (DATA, RESOURCE),
        "duplicate-data-3-4": (DATA[4:10], RESOURCE),
        "duplicate-data-4-3": (DATA[3:9], RESOURCE),
        "duplicate-data-beyond-inside": (b"", RESOURCE),
        "duplicate-resource-3-4": (DATA, RESOURCE[4:314]),
    }[name.removeprefix("resume-download-")]


def check_no_reply(report: Report) -> Report:
    """Check that an unusable descriptor drew no reply and left the session usable.

    Returns
    -------
    dict[str, typing.Any]
        The outcome to report.
    """
    require(
        not any(f["is_reply"] and f["id"] == REQUEST_ID for f in report["frames"]),
        "Unexpected invalid-RFLT reply",
    )
    require(
        reply(report, FOLLOWUP_ID)["payload_hex"] == ACK_PAYLOAD_HEX,
        "Control session did not remain usable",
    )
    pause = next(e for e in report["events"] if e["event"] == "pause")
    prior = [e for e in report["events"] if e["action"] < pause["action"]][-1]
    require(
        pause["elapsed_ns"] - prior["elapsed_ns"]
        >= PAUSE_SECONDS * NANOSECONDS_PER_SECOND,
        "Short invalid-input window",
    )
    return {
        "outcome": "No reply10 observed before three-second pause and subsequent500 ACK"
    }


def check_overflow(report: Report, packets: Report, advertised: int) -> Report:
    """Check that an unsigned-maximum offset closes the data connection.

    Returns
    -------
    dict[str, typing.Any]
        The outcome to report.
    """
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(
        advertised == EMPTY_FORKS_BYTES and not received,
        "Unsigned-max offset outcome differs",
    )
    require(
        packets["download"]["guest_server_initiated_close"],
        "Missing native offset-error close",
    )
    require(
        any(e["event"] == "eof" for e in report["events"]),
        "Missing offset-error EOF",
    )
    return {
        "advertised_bytes": advertised,
        "delivered_bytes": 0,
        "outcome": "Data connection closed without advertised stream",
    }


def check_download(
    name: str, report: Report, expectation: Report, packets: Report
) -> Report:
    """Check one resume download against the fork ranges it should select.

    Returns
    -------
    dict[str, typing.Any]
        The advertised, data and resource byte counts, or the failure outcome.
    """
    if expectation["kind"] == "resume-no-reply":
        return check_no_reply(report)
    values = fields(reply(report, REQUEST_ID))
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and int.from_bytes(reference, "big") & 1 != 0,
        "Download ref parity",
    )
    require(
        int.from_bytes(values[FIELD_FILE_SIZE], "big") == LOGICAL_BYTES,
        "Logical file length changed",
    )
    sent = bytes.fromhex(report["streams"]["download"]["sent_hex"])
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    require(sent == HTXF_MAGIC + reference + HTXF_TAIL, "Download header differs")
    advertised = int.from_bytes(values[FIELD_TRANSFER_SIZE], "big")
    if expectation["kind"] == "resume-data-error":
        return check_overflow(report, packets, advertised)
    require(len(received) == advertised, "Resume advertised count differs")
    forks = decode(received)
    expected_data, expected_resource = expected_forks(name)
    require(
        forks["DATA"] == expected_data and forks["MACR"] == expected_resource,
        "Resume fork range differs",
    )
    check_metadata(forks["INFO"], FORK_NAME, uploaded=False)
    require(
        not packets["download"]["guest_server_initiated_close"],
        "Resume download closed before client",
    )
    return {
        "advertised_bytes": advertised,
        "data_bytes": len(expected_data),
        "resource_bytes": len(expected_resource),
    }


@dc.dataclass(frozen=True, slots=True)
class Upload:
    """What an upload case sent.

    Attributes
    ----------
    report : dict[str, typing.Any]
        The capture report.
    expectation : dict[str, typing.Any]
        The planner's expectation.
    packets : dict[str, typing.Any]
        The packet observations of each connection.
    filename : bytes
        The file that the case uploads.
    sent : bytes
        Everything that the upload connection sent.
    advertised : int
        The size word of the HTXF header.
    """

    report: Report
    expectation: Report
    packets: Report
    filename: bytes
    sent: bytes
    advertised: int


def check_refusal(response: Report, filename: bytes) -> Report:
    """Check that resuming a missing or completed file is refused with a message.

    Returns
    -------
    dict[str, typing.Any]
        The phrase that the refusal carried.
    """
    require(response["error"] == ERROR_REPLY, "Missing/completed file resume accepted")
    values = {f["id"]: bytes.fromhex(f["hex"]) for f in response["fields"]}
    require(
        set(values) == {FIELD_ERROR_TEXT},
        "Resume failure unexpectedly allocated reference",
    )
    phrase = (
        b"does not exist" if filename == MISSING_NAME else b"already fully transfered"
    )
    require(phrase in values[FIELD_ERROR_TEXT], "Resume failure message differs")
    return {"outcome": phrase.decode()}


def check_seed(upload: Upload) -> Report:
    """Check that the seed sent a prefix and left an incomplete native file.

    Returns
    -------
    dict[str, typing.Any]
        The byte counts of the seeded state.
    """
    sent = upload.sent
    require(
        sent[HTXF_HEADER_BYTES:].hex() == upload.expectation["prefix_hex"]
        and upload.advertised == SEED_STREAM_BYTES,
        "Seed prefix differs",
    )
    require(
        len(sent) - HTXF_HEADER_BYTES == SEED_SENT_BYTES,
        "Unexpected partial upload count",
    )
    info = fields(reply(upload.report, FOLLOWUP_ID))
    require(
        info[FIELD_FILE_TYPE] == SEED_TYPE
        and int.from_bytes(info[FIELD_FILE_SIZE], "big") == SEED_LOGICAL_BYTES,
        "Incomplete file state differs",
    )
    require(
        not upload.packets["upload"]["guest_server_initiated_close"],
        "Seed closed before interruption",
    )
    return {
        "advertised_bytes": upload.advertised,
        "sent_body_bytes": SEED_SENT_BYTES,
        "retained_data_bytes": DATA_OFFSET,
        "retained_resource_bytes": RESOURCE_OFFSET,
    }


def check_readback(upload: Upload, expected: tuple[bytes, bytes]) -> None:
    """Check that downloading the resumed file returns the expected forks."""
    report = upload.report
    download = bytes.fromhex(report["streams"]["download"]["received_hex"])
    control = fields(reply(report, READBACK_ID))
    require(
        len(download) == int.from_bytes(control[FIELD_TRANSFER_SIZE], "big"),
        "Readback count differs",
    )
    require(
        bytes.fromhex(report["streams"]["download"]["sent_hex"])
        == HTXF_MAGIC + control[FIELD_TRANSFER_REFERENCE] + HTXF_TAIL,
        "Readback reference differs",
    )
    forks = decode(download)
    require(
        forks["DATA"] == expected[0] and forks["MACR"] == expected[1],
        "Resumed native readback differs",
    )
    check_metadata(forks["INFO"], upload.filename, uploaded=False)


def check_continuation(upload: Upload) -> Report:
    """Check the continuation bytes of a resumed upload and the file they build.

    Returns
    -------
    dict[str, typing.Any]
        The byte counts of the finished file and whether the client was
        inconsistent.
    """
    body = upload.sent[HTXF_HEADER_BYTES:]
    require(
        body.hex() == upload.expectation["stream_hex"]
        and len(body) == upload.advertised,
        "Continuation body differs",
    )
    uploaded = decode(body)
    inconsistent = upload.expectation["inconsistent"]
    require(
        uploaded["DATA"] == (DATA if inconsistent else b""), "Continuation DATA differs"
    )
    require(
        uploaded["MACR"] == (RESOURCE if inconsistent else RESOURCE[RESOURCE_OFFSET:]),
        "Continuation MACR differs",
    )
    check_metadata(uploaded["INFO"], upload.filename, uploaded=True)
    require(
        upload.packets["upload"]["guest_server_initiated_close"],
        "Continuation did not close upload",
    )
    expected_data = DATA + DATA if inconsistent else DATA
    expected_resource = (
        RESOURCE[:RESOURCE_OFFSET] + RESOURCE if inconsistent else RESOURCE
    )
    check_file_info(
        reply(upload.report, FOLLOWUP_ID),
        upload.filename,
        len(expected_data) + len(expected_resource),
    )
    check_readback(upload, (expected_data, expected_resource))
    return {
        "data_bytes": len(expected_data),
        "resource_bytes": len(expected_resource),
        "inconsistent_client": inconsistent,
    }


def check_upload(report: Report, expectation: Report, packets: Report) -> Report:
    """Check one resume upload case.

    Returns
    -------
    dict[str, typing.Any]
        The observations that the case reports.
    """
    kind = expectation["kind"]
    filename = bytes.fromhex(expectation["name_hex"])
    response = reply(report, REQUEST_ID)
    if kind == "resume-upload-probe" and filename != RESUME_PARTIAL_NAME:
        return check_refusal(response, filename)
    values = fields(response)
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and not int.from_bytes(reference, "big") & 1,
        "Upload ref parity",
    )
    if kind != "upload-prefix":
        require(
            values[FIELD_RESUME_DATA]
            == rflt([(b"DATA", DATA_OFFSET), (b"MACR", RESOURCE_OFFSET)]),
            "Negotiated offsets differ",
        )
    if kind == "resume-upload-probe":
        return {
            "negotiated_data_offset": DATA_OFFSET,
            "negotiated_resource_offset": RESOURCE_OFFSET,
        }
    sent = bytes.fromhex(report["streams"]["upload"]["sent_hex"])
    require(
        sent[:HTXF_SIZE_START] == HTXF_MAGIC + reference
        and sent[HTXF_TAIL_START:HTXF_HEADER_BYTES] == bytes(4),
        "Upload header differs",
    )
    advertised = int.from_bytes(sent[HTXF_SIZE_START:HTXF_SIZE_END], "big")
    upload = Upload(report, expectation, packets, filename, sent, advertised)
    return check_seed(upload) if kind == "upload-prefix" else check_continuation(upload)
