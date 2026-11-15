"""Check one recorded cleanup download or upload case.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import typing as typ

from native_cleanup_cases import FILENAME, UPLOAD_DATA, data_fork
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    FIELD_FILE_SIZE,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
)
from pcap_tcp import direction
from verify_native_cleanup_timing import (
    TCP_FIN,
    TCP_RST,
    bytes_after,
    flow,
    request_time,
)
from verify_native_core import require
from verify_native_forks import check_file_info, fields
from verify_native_queues import frame_time

type Report = dict[str, typ.Any]
type Flow = tuple[list[Report], tuple, tuple]

FULL_VARIANTS = {"baseline", "nonowner"}  # the downloads that run to completion
REFERENCE_BYTES = 4
REQUEST_ID = 10
OWNER_ACK_ID = 21
DUPLICATE_ACK_ID = 22
NONOWNER_ACK_ID = 20
LOOKUP_ID = 11
SMALL_LOOKUP_ID = 12
SMALL_DUPLICATE_ID = 13
HTXF_MAGIC = b"HTXF"
HTXF_TAIL_BYTES = 8
SIZE_BYTES = 4
EMPTY_ACK_HEX = "0000"


def reply(report: Report, owner: str, identifier: int) -> Report:
    """Select the one reply that ``owner`` received for a request.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame, after its fields have been parsed.
    """
    selected = [
        f
        for f in report["frames"]
        if f["connection"] == owner and f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(selected) == 1, "Missing or duplicate cleanup reply")
    fields(selected[0])
    return selected[0]


def check_reference(report: Report, baseline: bytes) -> bytes:
    """Check the download reply's reference parity and sizes.

    Returns
    -------
    bytes
        The transfer reference.
    """
    values = fields(reply(report, "a", REQUEST_ID))
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and int.from_bytes(reference, "big") & 1 != 0,
        "Cleanup download reference parity differs",
    )
    require(
        int.from_bytes(values[FIELD_TRANSFER_SIZE], "big") == len(baseline),
        "Cleanup advertised size differs",
    )
    require(
        int.from_bytes(values[FIELD_FILE_SIZE], "big")
        == len(data_fork()) + len(resource_fork()),
        "Cleanup logical size differs",
    )
    return reference


def expected_before(expectation: Report, baseline: bytes) -> int:
    """Return how many bytes the application had read when the owner's ACK came.

    Returns
    -------
    int
        The whole baseline for a full download, else the prefix size.
    """
    if expectation["variant"] in FULL_VARIANTS:
        return len(baseline)
    return expectation["prefix_size"]


def check_received(
    report: Report, reference: bytes, baseline: bytes, expectation: Report
) -> bytes:
    """Check the data that reached the downloading connection.

    Returns
    -------
    bytes
        The received stream.
    """
    recorded = report["streams"]["reference"]
    require(
        bytes.fromhex(recorded["sent_hex"])
        == HTXF_MAGIC + reference + bytes(HTXF_TAIL_BYTES),
        "Cleanup HTXF differs",
    )
    received = bytes.fromhex(recorded["received_hex"])
    require(baseline.startswith(received), "Cancelled data is not a baseline prefix")
    if expectation["variant"] in FULL_VARIANTS:
        require(received == baseline, "Full/nonowner download was truncated")
        require(
            any(
                e["event"] == "quiet" and e["connection"] == "reference"
                for e in report["events"]
            ),
            "Missing completed/nonowner open-connection observation",
        )
    else:
        require(
            expectation["prefix_size"] <= len(received) < len(baseline),
            "Race did not establish bounded partial delivery",
        )
    return received


def check_acks(report: Report) -> Report:
    """Check the owner's and the duplicate cleanup ACKs.

    Returns
    -------
    dict[str, typing.Any]
        The owner's ACK frame.
    """
    response = reply(report, "a", OWNER_ACK_ID)
    require(
        response["payload_hex"] == EMPTY_ACK_HEX
        and reply(report, "a", DUPLICATE_ACK_ID)["payload_hex"] == EMPTY_ACK_HEX,
        "Owner/duplicate cleanup ACK differs",
    )
    return response


def check_closes(report: Report, packets: Report, reference: bytes) -> None:
    """Check the native close of the data connection and the refused stale reuse."""
    require(
        packets["reference"]["guest_server_initiated_close"],
        "Missing native cleanup close",
    )
    require(
        report["streams"]["stale"]["received_hex"] == ""  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # == "" rejects a non-string value that "not" would accept
        and packets["stale"]["guest_server_initiated_close"],
        "Removed reference reattached successfully",
    )
    require(
        bytes.fromhex(report["streams"]["stale"]["sent_hex"])
        == HTXF_MAGIC + reference + bytes(HTXF_TAIL_BYTES),
        "Stale-reference header differs",
    )


def read_after_ack(report: Report, response: Report) -> int:
    """Count the bytes that the application read after the owner's ACK.

    Returns
    -------
    int
        The summed length of the later ``receive`` events on the data connection.
    """
    return sum(
        len(bytes.fromhex(e["hex"]))
        for e in report["events"]
        if e["connection"] == "reference"
        and e["event"] == "receive"
        and e["action"] > response["action"]
    )


def measure(
    report: Report, response: Report, received: bytes, guest: list[Report]
) -> tuple[Report, Flow]:
    """Measure what the guest delivered around the owner's request and ACK.

    Returns
    -------
    tuple[dict[str, typing.Any], Flow]
        The three guest-side measurements, and the data connection's flow.
    """
    data = flow(report, "reference", guest)
    data_packets, client, server = data
    ack_time = frame_time(report, response, guest)
    observed_request = request_time(report, response, guest)
    outgoing = direction(data_packets, server, client)
    closes = [p for p in outgoing if p["flags"] & (TCP_FIN | TCP_RST)]
    require(bool(closes), "Missing native close packet")
    return {
        "guest_bytes_first_observed_after_owner_request": bytes_after(
            data_packets, server, client, len(received), observed_request
        ),
        "guest_bytes_first_observed_after_owner_ack": bytes_after(
            data_packets, server, client, len(received), ack_time
        ),
        "guest_close_minus_owner_ack_us": closes[0]["timestamp_us"] - ack_time,
    }, data


def check_nonowner(
    report: Report, data: Flow, received: bytes, guest: list[Report]
) -> int:
    """Check that the non-owner's cleanup left the native delivery running.

    Returns
    -------
    int
        The bytes first observed after the non-owner's ACK.
    """
    data_packets, client, server = data
    other = reply(report, "b", NONOWNER_ACK_ID)
    require(other["payload_hex"] == EMPTY_ACK_HEX, "Nonowner cleanup ACK differs")
    return bytes_after(
        data_packets, server, client, len(received), frame_time(report, other, guest)
    )


def check_download(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # pylint: disable=too-many-arguments,too-many-positional-arguments  # the callers' shape
    report: Report,
    expectation: Report,
    baseline: bytes,
    packets: Report,
    guest: list[Report],
) -> Report:
    """Check one download variant against the guest packets.

    Returns
    -------
    dict[str, typing.Any]
        The measurements that the corpus summary reports.
    """
    variant = expectation["variant"]
    reference = check_reference(report, baseline)
    received = check_received(report, reference, baseline, expectation)
    response = check_acks(report)
    check_closes(report, packets, reference)
    after = read_after_ack(report, response)
    require(
        len(received) - after == expected_before(expectation, baseline),
        "Application receive/cancel ordering differs",
    )
    measured, data = measure(report, response, received, guest)
    result = {
        "received_stream_bytes": len(received),
        "application_bytes_read_after_owner_ack": after,
        **measured,
    }
    if variant == "nonowner":
        observed = check_nonowner(report, data, received, guest)
        result["guest_bytes_first_observed_after_nonowner_ack"] = observed
        require(observed > 0, "Nonowner case did not overlap native data delivery")
    return result


def upload_subject(expectation: Report) -> tuple[bool, bytes, bytes]:
    """Name the file and data that an upload case stores.

    Returns
    -------
    tuple[bool, bytes, bytes]
        Whether this is the small 214 case, the file name and the data fork.
    """
    small = expectation["kind"] == "cleanup-upload"
    filename = bytes.fromhex(expectation["name_hex"]) if small else FILENAME
    data = UPLOAD_DATA if small else data_fork()
    return small, filename, data


def upload_reference(report: Report) -> bytes:
    """Check the upload reply's reference, which is even.

    Returns
    -------
    bytes
        The transfer reference.
    """
    values = fields(reply(report, "a", REQUEST_ID))
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and not int.from_bytes(reference, "big") & 1,
        "Cleanup upload reference differs",
    )
    return reference


def check_upload_stream(
    report: Report, packets: Report, reference: bytes, data: bytes
) -> None:
    """Check the upload connection's greeting, body and native close."""
    body = file_stream(data, resource_fork())
    require(
        bytes.fromhex(report["streams"]["upload"]["sent_hex"])
        == HTXF_MAGIC
        + reference
        + len(body).to_bytes(SIZE_BYTES, "big")
        + bytes(SIZE_BYTES)
        + body,
        "Cleanup upload body differs",
    )
    require(
        not report["streams"]["upload"]["received_hex"]
        and packets["upload"]["guest_server_initiated_close"],
        "Cleanup upload completion differs",
    )


def check_upload(report: Report, expectation: Report, packets: Report) -> Report:
    """Check one upload case.

    Returns
    -------
    dict[str, typing.Any]
        The measurements that the corpus summary reports.
    """
    small, filename, data = upload_subject(expectation)
    reference = upload_reference(report)
    check_upload_stream(report, packets, reference, data)
    check_file_info(
        reply(report, "a", SMALL_LOOKUP_ID if small else LOOKUP_ID),
        filename,
        len(data) + len(resource_fork()),
    )
    if small:
        require(
            reply(report, "a", LOOKUP_ID)["payload_hex"] == EMPTY_ACK_HEX
            and reply(report, "a", SMALL_DUPLICATE_ID)["payload_hex"] == EMPTY_ACK_HEX,
            "Upload214 ACK differs",
        )
    return {"uploaded_data_bytes": len(data), "pending_upload_survived214": small}
