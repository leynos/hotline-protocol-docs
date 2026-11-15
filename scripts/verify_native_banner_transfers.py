"""Check the banner data connection of one native capture against its case kind.

A banner case either delivers the GIF, is refused, expires after its owner has
been kept responsive, or changes or restores its buffer. Each kind is checked
against the frames and streams that were actually recorded.
"""

import dataclasses as dc
import typing as typ

from native_banner_cases import GIF_A, GIF_B, URL
from native_wire_names import (
    FIELD_BANNER_LINK,
    FIELD_BANNER_TYPE,
    FIELD_TRANSFER_REFERENCE,
    FIELD_TRANSFER_SIZE,
    HTXF_MAGIC_HEX,
)
from verify_native_core import require

type Report = dict[str, typ.Any]

HANDSHAKE_BYTES = 12  # the 12-byte session greeting precedes the first request
REFERENCE_BYTES = 4
HTXF_BYTES = 16
HTXF_MAGIC = bytes.fromhex(HTXF_MAGIC_HEX)
HTXF_REFERENCE_START = 4
HTXF_REFERENCE_END = 8
HTXF_SELECTOR_START = 12
HTXF_SELECTOR_END = 14
BANNER_SELECTOR = b"\0\2"  # selector 2 with an odd reference is a banner download
OWNER_REQUEST = 10  # the 212 request of every case
LIVENESS_REQUEST = 90  # the empty ACK that follows a bounded silence
CANCEL_REQUESTS = {11, 12}
EXPIRY_FIRST_ID = 20
EXPIRY_LAST_ID = 31
EXPIRY_PAUSES = 12
RESTORATION_PAUSES = 2  # the failed load, then the restoration
EXPIRY_PAUSE_SECONDS = 45
NANOSECONDS_PER_SECOND = 1e9
INITIAL_CASES = 42
CATALOGS = [(11240, GIF_A, "a"), (11241, GIF_B, "b")]
FILENAME_HELPERS = ["1002af80", "1002e8b0", "1002f080", "1002f0c0"]


def fields(frame: Report) -> dict[int, bytes]:
    """Index the fields of a decoded frame by ID.

    Returns
    -------
    dict[int, bytes]
        The value of each field.
    """
    values = {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
    require(len(values) == len(frame["fields"]), "Duplicate banner field")
    return values


@dc.dataclass(frozen=True, slots=True)
class Case:
    """One banner capture and what the planner expected of it.

    Attributes
    ----------
    name : str
        The case name.
    report : dict[str, typing.Any]
        The capture report.
    packets : dict[str, typing.Any]
        The packet observations of each connection.
    expectation : dict[str, typing.Any]
        The planner's expectation.
    banners : list[dict[str, typing.Any]]
        The 122 notifications of the capture.
    """

    name: str
    report: Report
    packets: Report
    expectation: Report
    banners: list[Report]


@dc.dataclass(frozen=True, slots=True)
class Transfer:
    """The banner data connection of one case.

    Attributes
    ----------
    case : Case
        The capture that it belongs to.
    reference : bytes
        The banner reference that the 212 ACK returned.
    advertised : int
        The size that the 212 ACK advertised.
    sent : bytes
        What the banner connection sent.
    raw : bytes
        What the banner connection received.
    """

    case: Case
    reference: bytes
    advertised: int
    sent: bytes
    raw: bytes


def read_transfer(case: Case) -> Transfer:
    """Check the 212 ACK and the HTXF greeting, and gather the data connection.

    Returns
    -------
    Transfer
        The connection with the reference and size that the ACK returned.
    """
    name, report = case.name, case.report
    acks = [f for f in report["frames"] if f["is_reply"] and f["id"] == OWNER_REQUEST]
    require(len(acks) == 1 and acks[0]["error"] == 0, name + ":212 ACK differs")
    values = fields(acks[0])
    require(
        set(values) == {FIELD_TRANSFER_REFERENCE, FIELD_TRANSFER_SIZE},
        name + ":212 fields differ",
    )
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == REFERENCE_BYTES and int.from_bytes(reference, "big") & 1 == 1,
        name + ": reference differs",
    )
    stream = report["streams"]["banner"]
    sent = bytes.fromhex(stream["sent_hex"])
    require(
        len(sent) == HTXF_BYTES and sent[:HTXF_REFERENCE_START] == HTXF_MAGIC,
        name + ": HTXF header differs",
    )
    return Transfer(
        case,
        reference,
        int.from_bytes(values[FIELD_TRANSFER_SIZE], "big"),
        sent,
        bytes.fromhex(stream["received_hex"]),
    )


def check_reject(transfer: Transfer) -> None:
    """Check that a negative control sent the reference and selector it planned."""
    name, sent = transfer.case.name, transfer.sent
    if name.endswith("-unknown"):
        expected_ref = b"\xff" * REFERENCE_BYTES
    elif name.endswith("-zero"):
        expected_ref = bytes(REFERENCE_BYTES)
    else:
        expected_ref = transfer.reference
    selector = int.from_bytes(sent[HTXF_SELECTOR_START:HTXF_SELECTOR_END], "big")
    require(
        sent[HTXF_REFERENCE_START:HTXF_REFERENCE_END] == expected_ref
        and selector == transfer.case.expectation["selector"],
        name + ": negative HTXF control differs",
    )


def check_attached(transfer: Transfer, kind: str) -> None:
    """Check the bytes and notifications of a banner that was delivered."""
    name, report = transfer.case.name, transfer.case.report
    sent = transfer.sent
    require(
        sent[HTXF_REFERENCE_START:HTXF_REFERENCE_END] == transfer.reference
        and sent[HTXF_SELECTOR_START:HTXF_SELECTOR_END] == BANNER_SELECTOR,
        name + ": attached reference/selector differs",
    )
    expected = GIF_B if kind in {"changed", "absent-restored"} else GIF_A
    require(transfer.raw == expected, name + ": raw banner bytes differ")
    require(
        transfer.advertised
        == (len(GIF_B) if kind == "absent-restored" else len(GIF_A)),
        name + ": advertised size differs",
    )
    require(
        any(
            e["event"] == "quiet" and e["connection"] == "banner"
            for e in report["events"]
        ),
        name + ": missing open-stream observation",
    )
    if kind == "changed":
        require(
            len(transfer.case.banners) == 1
            and fields(transfer.case.banners[0])
            == {FIELD_BANNER_TYPE: b"GIFf", FIELD_BANNER_LINK: URL},
            name + ": reload metadata sequence differs",
        )
    else:
        require(
            not transfer.case.banners, name + ": early login unexpectedly emitted122"
        )
    if kind == "absent-restored":
        check_restoration(name, report)
    if kind == "cancel-does-not-close":
        cancellations = [
            f
            for f in report["frames"]
            if f["is_reply"] and f["id"] in CANCEL_REQUESTS and f["error"] == 0
        ]
        require(
            len(cancellations) == len(CANCEL_REQUESTS),
            name + ": cancellation ACKs differ",
        )


def check_restoration(name: str, report: Report) -> None:
    """Check that the banner was restored during the second pause."""
    receives = [
        e
        for e in report["events"]
        if e["event"] == "receive" and e["connection"] == "banner"
    ]
    pauses = [e for e in report["events"] if e["event"] == "pause"]
    quiets = [
        e
        for e in report["events"]
        if e["event"] == "quiet" and e["connection"] == "banner"
    ]
    require(
        len(pauses) == RESTORATION_PAUSES
        and quiets[0]["elapsed_ns"]
        < pauses[1]["elapsed_ns"]
        < receives[0]["elapsed_ns"],
        name + ": restoration ordering differs",
    )


def check_expiry(name: str, report: Report) -> None:
    """Check that the owner stayed responsive while the reference aged out."""
    require(
        {
            f["id"]
            for f in report["frames"]
            if f["is_reply"]
            and f["error"] == 0
            and EXPIRY_FIRST_ID <= f["id"] <= EXPIRY_LAST_ID
        }
        == set(range(EXPIRY_FIRST_ID, EXPIRY_LAST_ID + 1)),
        name + ": missing owner liveness ACKs",
    )
    pauses = [e for e in report["events"] if e["event"] == "pause"]
    require(len(pauses) == EXPIRY_PAUSES, name + ": expiry windows differ")
    for event in pauses:
        prior = max(
            e["elapsed_ns"]
            for e in report["events"]
            if e["action"] == event["action"] - 1
        )
        require(
            event["elapsed_ns"] - prior
            >= EXPIRY_PAUSE_SECONDS * NANOSECONDS_PER_SECOND,
            name + ": shortened expiry pause",
        )


def check_transfer(transfer: Transfer, kind: str) -> None:
    """Check the data connection of a banner case against its kind."""
    name = transfer.case.name
    if kind == "reject":
        check_reject(transfer)
    if kind == "expired":
        require(
            transfer.sent[HTXF_REFERENCE_START:HTXF_REFERENCE_END] == transfer.reference
            and transfer.sent[HTXF_SELECTOR_START:HTXF_SELECTOR_END] == BANNER_SELECTOR,
            name + ": expiry reference differs",
        )
    if kind in {"reject", "expired"}:
        require(
            not transfer.raw
            and transfer.case.packets["banner"]["guest_server_initiated_close"],
            name + ": rejection outcome differs",
        )
    else:
        check_attached(transfer, kind)
    if kind == "expired":
        check_expiry(name, transfer.case.report)
