"""Check one recorded HTXF case: its reference, header, delivery and ordering.

The order of the checks in each function is the order in which a corrupt case
is refused, so a function reads its evidence in the sequence that it always has.
"""

import dataclasses as dc
import typing as typ

from native_banner_cases import GIF_B
from native_filp import decode
from native_transfer_cases import file_stream, resource_fork
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_LOGIN,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
    SELECTOR_BANNER,
    TYPE_DOWNLOAD_BANNER,
    TYPE_DOWNLOAD_FILE,
    TYPE_DOWNLOAD_FOLDER,
    TYPE_PRIVILEGES_NOTIFICATION,
    TYPE_UPLOAD_FILE,
)
from verify_native_banner_formats import requests
from verify_native_banners import fields
from verify_native_core import require
from verify_native_htxf_events import (
    check_ordering,
    check_quiet_windows,
    observed,
)

type Report = dict[str, typ.Any]
type Fields = dict[int, bytes]

REQUEST_ID = 10
UPLOAD_LOOKUP_ID = 11
REFERENCE_BYTES = 4
HEADER_BYTES = 16  # the magic, reference, size, selector and reserved words
OBSERVER_LOGIN = b"fixture-low"
COMPLEMENT_MASK = 0xFF
SIZE_ANY = 0xFFFFFFFF
RESERVED_ANY = 65535
SELECTOR_ANY = 65535
SELECTOR_NONE = 0
SIZE_BYTES = 4
WORD_BYTES = 2
SELECTOR_PADDING = 37  # extra bytes that the selector-0 upload advertised
TRANSFER_TYPES = {
    TYPE_DOWNLOAD_FILE,
    TYPE_UPLOAD_FILE,
    TYPE_DOWNLOAD_FOLDER,
    TYPE_DOWNLOAD_BANNER,
}
# The cases whose first attachment is delivered the whole transfer.
DELIVERING_CASES = {
    "banner-size-ffffffff-reserved-ffff",
    "banner-size-one-reserved-1234",
    "banner-split-15-plus-1",
    "download-size-reserved-selector-ffff",
    "download-separate-low-privilege-session",
}
DELIVERING_CONNECTIONS = {"first", "foreign"}
DOWNLOAD_DATA = b"data-fork\r\n\x00\xff"


@dc.dataclass(frozen=True, slots=True)
class Words:
    """The size, selector, reserved word and magic that a case's header carries."""

    size: int = 0
    selector: int = 0
    reserved: int = 0
    magic: bytes = bytes.fromhex(HTXF_MAGIC_HEX)

    def encode(self, reference: bytes) -> bytes:
        """Encode the header that a connection should have sent.

        Returns
        -------
        bytes
            The magic, reference, size, selector and reserved words.
        """
        return (
            self.magic
            + reference
            + self.size.to_bytes(SIZE_BYTES, "big")
            + self.selector.to_bytes(WORD_BYTES, "big")
            + self.reserved.to_bytes(WORD_BYTES, "big")
        )


FIXED_WORDS = {
    "banner-size-ffffffff-reserved-ffff": Words(size=SIZE_ANY, reserved=RESERVED_ANY),
    "banner-size-one-reserved-1234": Words(size=1, reserved=0x1234),
    "banner-split-15-plus-1": Words(size=0, reserved=0x1234),
    "banner-bad-magic": Words(magic=b"HTXG"),
    "download-size-reserved-selector-ffff": Words(
        selector=SELECTOR_ANY, size=SIZE_ANY, reserved=0xABCD
    ),
}


@dc.dataclass(frozen=True, slots=True)
class Case:
    """One case under check: its capture, packet facts and decoded reference."""

    name: str
    report: Report
    packets: Report
    operation: Report
    values: Fields
    words: Words

    @property
    def reference(self) -> bytes:
        """The transfer reference of the case's ACK."""
        return self.values[FIELD_TRANSFER_REFERENCE]


def ack(report: Report, identifier: int = 10, connection: str = "a") -> Fields:
    """Select the one success ACK that ``connection`` received.

    Returns
    -------
    dict[int, bytes]
        The fields of the ACK by ID.
    """
    matches = [
        f
        for f in report["frames"]
        if f["connection"] == connection and f["is_reply"] and f["id"] == identifier
    ]
    require(len(matches) == 1 and matches[0]["error"] == 0, "Missing HTXF success ACK")
    return fields(matches[0])


def check_operation(report: Report, reference: bytes) -> Report:
    """Find the transfer request that ``a`` sent, and check its reference parity.

    Returns
    -------
    dict[str, typing.Any]
        The request frame.
    """
    operation = next(f for f in requests(report, "a") if f["id"] == REQUEST_ID)
    require(operation["type"] in TRANSFER_TYPES, "Wrong HTXF request")
    require(
        int.from_bytes(reference, "big") & 1 == (operation["type"] != TYPE_UPLOAD_FILE),
        "Reference parity differs",
    )
    return operation


def check_observer(report: Report) -> None:
    """Check the second session's privileges and identity, when there is one."""
    if "b" not in report["streams"]:
        return
    privilege = [
        f
        for f in report["frames"]
        if f["connection"] == "b" and f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    ]
    require(
        len(privilege) == 1
        and fields(privilege[0]) == {FIELD_ACCESS_BITMAP: bytes(ACCESS_BITMAP_BYTES)},
        "Observer privileges differ",
    )
    credentials = fields(requests(report, "b")[0])
    require(
        credentials[FIELD_LOGIN] == bytes(v ^ COMPLEMENT_MASK for v in OBSERVER_LOGIN),
        "Observer identity differs",
    )


def header_words(name: str, operation: Report) -> Words:
    """Work out the header that the case's data connection should have sent.

    Returns
    -------
    Words
        The size, selector, reserved word and magic.
    """
    selector = SELECTOR_BANNER if operation["type"] == TYPE_DOWNLOAD_BANNER else 0
    fixed = FIXED_WORDS.get(name)
    if fixed is not None:
        return dc.replace(fixed, selector=fixed.selector or selector)
    if name.startswith("folder-download-wrong-selector-"):
        return Words(selector=int(name.rsplit("-", 1)[1]))
    if name.startswith("upload-nonfolder-selector-"):
        selector = int(name.rsplit("-", 1)[1])
        body = file_stream(upload_data(selector), b"")
        return Words(selector=selector, size=len(body), reserved=RESERVED_ANY)
    return Words(selector=selector)


def upload_data(selector: int) -> bytes:
    """Name the data fork that the upload for ``selector`` stores.

    Returns
    -------
    bytes
        The routing text followed by the selector.
    """
    return b"header-routing-" + str(selector).encode()


def check_upload_stream(
    case: Case, connection: str, sent: bytes, received: bytes
) -> None:
    """Check an upload connection's body, advertised size and close."""
    selector = case.words.selector
    body = file_stream(upload_data(selector), b"")
    require(sent[HEADER_BYTES:] == body and not received, "Upload stream differs")
    advertised = int.from_bytes(fields(case.operation)[FIELD_TRANSFER_SIZE], "big")
    require(
        advertised
        == len(body) + (SELECTOR_PADDING if selector == SELECTOR_NONE else 0),
        "Upload request size differs",
    )
    require(bool(observed(case.report, connection, "eof")), "Missing upload close")
    ack(case.report, UPLOAD_LOOKUP_ID)


def check_delivery(case: Case, received: bytes) -> None:
    """Check the bytes that a successful attachment received."""
    if case.operation["type"] == TYPE_DOWNLOAD_BANNER:
        require(received == GIF_B, "Banner bytes differ")
        return
    forks = decode(received)
    require(
        forks["DATA"] == DOWNLOAD_DATA and forks["MACR"] == resource_fork(),
        "Download forks differ",
    )
    require(
        len(received) == int.from_bytes(case.values[FIELD_TRANSFER_SIZE], "big"),
        "Download advertised size differs",
    )


def expected_event(case: Case, connection: str, *, succeeds: bool) -> str:
    """Name the observation that ends a download connection.

    Returns
    -------
    str
        ``quiet``, ``eof`` or ``close``.
    """
    event = "quiet" if succeeds and connection != "download" else "eof"
    if case.name == "banner-reuse-after-close" and connection == "first":
        event = "close"
    return event


def check_download_stream(
    case: Case, connection: str, sent: bytes, received: bytes
) -> bool:
    """Check a banner or file connection's input, delivery and last event.

    Returns
    -------
    bool
        Whether the connection was delivered the transfer.
    """
    require(len(sent) == HEADER_BYTES, "Unexpected HTXF input suffix")
    succeeds = connection in DELIVERING_CONNECTIONS or case.name in DELIVERING_CASES
    if succeeds:
        check_delivery(case, received)
    else:
        require(not received, "Rejected/duplicate connection delivered bytes")
    require(
        bool(
            observed(
                case.report,
                connection,
                expected_event(case, connection, succeeds=succeeds),
            )
        ),
        "Missing HTXF quiet/close observation",
    )
    return succeeds


def check_streams(case: Case) -> list[str]:
    """Check every data connection of the case.

    Returns
    -------
    list[str]
        The connections that were delivered the transfer.
    """
    header = case.words.encode(case.reference)
    successful = []
    for connection, value in case.report["streams"].items():
        if connection in {"a", "b"}:
            continue
        sent, received = (
            bytes.fromhex(value["sent_hex"]),
            bytes.fromhex(value["received_hex"]),
        )
        require(
            sent[:HEADER_BYTES] == header,
            case.name + ": physical HTXF header differs",
        )
        if case.operation["type"] == TYPE_UPLOAD_FILE:
            check_upload_stream(case, connection, sent, received)
        elif check_download_stream(case, connection, sent, received):
            successful.append(connection)
        if observed(case.report, connection, "eof"):
            require(
                case.packets[connection]["guest_server_initiated_close"],
                "Missing native close",
            )
    return successful


def check_case(name: str, report: Report, packets: Report) -> Report:
    """Check one recorded HTXF case.

    Returns
    -------
    dict[str, typing.Any]
        The case, its reference and the connections that were delivered.
    """
    require(report["status"] == "completed", "Incomplete HTXF observation")
    values = ack(report, connection="main" if name == "preflight" else "a")
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(len(reference) == REFERENCE_BYTES, "HTXF reference width differs")
    if name == "preflight":
        require(
            int.from_bytes(values[FIELD_TRANSFER_SIZE], "big") == len(GIF_B),
            "Preflight size differs",
        )
        return {"case": name, "reference_hex": reference.hex()}
    operation = check_operation(report, reference)
    check_observer(report)
    case = Case(name, report, packets, operation, values, header_words(name, operation))
    successful = check_streams(case)
    check_quiet_windows(report)
    check_ordering(name, report, packets)
    return {
        "case": name,
        "reference_hex": reference.hex(),
        "operation": operation["type"],
        "successful_connections": successful,
    }
