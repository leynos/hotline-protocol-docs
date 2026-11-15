"""Check the upload and download transfers of the fork corpus against their plans."""

import dataclasses as dc
import typing as typ

from native_filp import decode
from native_wire_names import (
    FIELD_FILE_SIZE,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    SELECTOR_BANNER,
    SELECTOR_FOLDER,
)
from verify_native_core import require
from verify_native_fork_support import (
    HTXF,
    check_file_info,
    check_metadata,
    fields,
    transfer_bytes,
)

type Report = dict[str, typ.Any]

REFERENCE_BYTES = 4
SIZE_START = 8  # the HTXF header's size word follows the magic and the reference
RESERVED_START = 12
HEADER_BYTES = 16
WRONG_COLLECTIONS = {SELECTOR_FOLDER, SELECTOR_BANNER}
UPLOAD_ACKS = 2  # the request ACK and the file-info reply
CLEANUP_ACKS = 2  # the request ACK and the owner 214 cleanup ACK


@dc.dataclass(frozen=True, slots=True)
class Transfer:
    """One planned transfer, the way its capture was observed.

    Attributes
    ----------
    name : str
        The case name.
    report : dict[str, typing.Any]
        The capture report.
    expectation : dict[str, typing.Any]
        The expectation recorded in the plan.
    packets : dict[str, typing.Any]
        The packet reconciliation of the capture.
    frames : list[dict[str, typing.Any]]
        The frames that follow the login.
    values : dict[int, bytes]
        The fields of the first of those frames.
    filename : bytes
        The name of the transferred file.
    data : bytes
        The data fork that the file should carry.
    resource : bytes
        The resource fork that the file should carry.
    """

    name: str
    report: Report
    expectation: Report
    packets: Report
    frames: list[Report]
    values: dict[int, bytes]
    filename: bytes
    data: bytes
    resource: bytes

    @property
    def logical(self) -> int:
        """The logical size of the file, the two forks together."""
        return len(self.data) + len(self.resource)


def check_upload(transfer: Transfer) -> Report:
    """Check an upload: reference, HTXF header, stream, forks and file info.

    Returns
    -------
    dict[str, typing.Any]
        The file-info reply, in hexadecimal.
    """
    expectation = transfer.expectation
    sent, received = transfer_bytes(
        transfer.report, "upload", handover=expectation.get("handover", False)
    )
    reference = transfer.values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and not int.from_bytes(reference, "big") & 1,
        "Upload ref parity",
    )
    require(
        sent[len(HTXF) : SIZE_START] == reference
        and sent[RESERVED_START:HEADER_BYTES] == bytes(REFERENCE_BYTES),
        "Upload HTXF differs",
    )
    body = sent[HEADER_BYTES:]
    require(
        int.from_bytes(sent[SIZE_START:RESERVED_START], "big") == len(body),
        "Upload size differs",
    )
    require(body.hex() == expectation["stream_hex"], "Upload body differs")
    forks = decode(body)
    require(
        forks["DATA"] == transfer.data and forks["MACR"] == transfer.resource,
        "Uploaded forks differ",
    )
    check_metadata(forks["INFO"], transfer.filename, uploaded=True)
    require(not received, "Unexpected upload application response")
    require(
        transfer.packets["upload"]["guest_server_initiated_close"],
        "Upload completion did not close",
    )
    require(len(transfer.frames) == UPLOAD_ACKS, "Unexpected upload completion ACK")
    return check_file_info(transfer.frames[1], transfer.filename, transfer.logical)


def check_empty_preview(transfer: Transfer) -> None:
    """Check that a preview of the empty file allocated no transfer."""
    values = transfer.values
    require(
        set(values) == {FIELD_TRANSFER_SIZE}
        and values[FIELD_TRANSFER_SIZE] == bytes(2),
        "Empty preview metadata differs",
    )
    require(set(transfer.packets) == {"main"}, "Empty preview opened data connection")


def check_cleanup(transfer: Transfer, quiet: Report) -> None:
    """Check what followed the quiet window of a delivered download."""
    report, packets = transfer.report, transfer.packets
    if transfer.name == "download-raw":
        require(
            len(transfer.frames) == CLEANUP_ACKS and not fields(transfer.frames[1]),
            "Cleanup ACK differs",
        )
        require(
            any(
                e["event"] == "eof" and e["action"] > quiet["action"]
                for e in report["events"]
            ),
            "Missing post214 EOF",
        )
    else:
        require(
            not packets["download"]["guest_server_initiated_close"],
            "Download closed before peer cleanup",
        )


def check_delivery(transfer: Transfer, received: bytes) -> Report:
    """Check the bytes of a delivered download and what followed them.

    Returns
    -------
    dict[str, typing.Any]
        The decoded INFO metadata when the download carried the forks.
    """
    values, report = transfer.values, transfer.report
    require(
        len(received) == int.from_bytes(values[FIELD_TRANSFER_SIZE], "big"),
        "Advertised count differs",
    )
    observed = {}
    if transfer.expectation["preview"]:
        require(received == transfer.data, "Preview not raw data fork")
    else:
        forks = decode(received)
        require(
            forks["DATA"] == transfer.data and forks["MACR"] == transfer.resource,
            "Downloaded forks differ",
        )
        observed["metadata"] = check_metadata(
            forks["INFO"], transfer.filename, uploaded=False
        )
    quiet = next(e for e in report["events"] if e["event"] == "quiet")
    require(
        not any(
            e["event"] == "eof" and e["action"] <= quiet["action"]
            for e in report["events"]
        ),
        "EOF before quiet window",
    )
    check_cleanup(transfer, quiet)
    return observed


def check_download(transfer: Transfer) -> Report:
    """Check a download: reference, size, HTXF header and delivered bytes.

    Returns
    -------
    dict[str, typing.Any]
        The decoded INFO metadata when there is one, and the advertised size.
    """
    values, expectation = transfer.values, transfer.expectation
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and int.from_bytes(reference, "big") & 1 != 0,
        "Download ref parity",
    )
    require(
        int.from_bytes(values[FIELD_FILE_SIZE], "big") == transfer.logical,
        "Logical download size differs",
    )
    sent, received = transfer_bytes(
        transfer.report, "download", handover=expectation["handover"]
    )
    require(
        sent
        == HTXF
        + reference
        + bytes(REFERENCE_BYTES)
        + expectation["selector"].to_bytes(2, "big")
        + bytes(2),
        "Download HTXF differs",
    )
    observed: Report = {}
    if expectation["selector"] in WRONG_COLLECTIONS:
        require(
            not received
            and transfer.packets["download"]["guest_server_initiated_close"],
            "Wrong collection not rejected",
        )
    else:
        observed = check_delivery(transfer, received)
    observed["advertised_bytes"] = int.from_bytes(values[FIELD_TRANSFER_SIZE], "big")
    return observed
