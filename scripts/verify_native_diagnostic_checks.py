"""Checks of the diagnostic verifiers: transfer references, 303 targets and 214 cancels.

Every check calls :func:`require` at its first failure, so the order of the calls
decides which message a failing report produces. The verifiers in
``verify_native_diagnostic_existing`` and ``verify_native_diagnostic_near`` re-export
these names, which is the only route by which other scripts reach them.
"""

from native_wire_names import (
    FIELD_QUEUE_POSITION,
    FIELD_USER_RECORD,
    TYPE_REFERENCE_CLEANUP,
)
from protocol_capture import decode_frame

STREAM_BYTES = 1_049_073  # the stream size that each 202 transfer reply reports
FORK_BYTES = 1_048_893  # the fork size that each 202 transfer reply reports
UINT32_BYTES = 4  # width of a big-endian 32-bit size field or transfer reference
UID_BYTES = 2  # width of the account identifier that starts a roster entry
DIAGNOSTIC_TYPE = 303  # the request type whose target the checks read; not named
# frame bytes 2 to 4 hold the transaction type and bytes 4 to 8 the identifier
TYPE_SLICE = slice(2, 4)
IDENTIFIER_SLICE = slice(4, 8)


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the public signature takes the flag positionally
    message: str,
) -> None:
    """Raise ``ValueError`` with ``message`` unless ``condition`` holds.

    Parameters
    ----------
    condition : bool
        The condition that must hold.
    message : str
        The message of the error raised when it does not hold.

    Raises
    ------
    ValueError
        When ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def reply(report: dict, identifier: int, *, success: bool = True) -> dict:
    """Return the reply with ``identifier``, which must succeed unless told so.

    Parameters
    ----------
    report : dict
        The verified report, with its ``frames``.
    identifier : int
        The transaction identifier of the reply.
    success : bool
        Whether the reply must carry error code 0.

    Returns
    -------
    dict
        The matching reply frame.
    """
    found = [
        frame
        for frame in report["frames"]
        if frame["is_reply"] == 1 and frame["id"] == identifier
    ]
    require(len(found) == 1, f"Expected one reply {identifier}")
    if success:
        require(found[0]["error"] == 0, f"Reply {identifier} failed")
    return found[0]


def values(frame: dict) -> dict[int, bytes]:
    """Return the fields of ``frame`` keyed by field identifier.

    Parameters
    ----------
    frame : dict
        A frame with its ``fields``, each carrying an ``id`` and a ``hex`` value.

    Returns
    -------
    dict[int, bytes]
        The decoded value of each field; a repeated identifier is an error.
    """
    result: dict[int, bytes] = {}
    for field in frame["fields"]:
        require(field["id"] not in result, "Duplicate scalar field")
        result[field["id"]] = bytes.fromhex(field["hex"])
    return result


def current_uid(report: dict) -> bytes:
    """Return the account identifier of the current roster, from reply 10.

    Parameters
    ----------
    report : dict
        The verified report.

    Returns
    -------
    bytes
        The first ``UID_BYTES`` of the single roster entry.
    """
    fields = reply(report, 10)["fields"]
    require(
        len(fields) == 1 and fields[0]["id"] == FIELD_USER_RECORD,
        "Ambiguous current roster",
    )
    encoded = bytes.fromhex(fields[0]["hex"])
    require(len(encoded) >= UID_BYTES, "Short current roster")
    return encoded[:UID_BYTES]


def _check_transfer_fields(item: dict[int, bytes], identifier: int) -> None:
    """Check the transfer fields of one 202 reply.

    Parameters
    ----------
    item : dict[int, bytes]
        The decoded fields of the reply.
    identifier : int
        The transaction identifier of the reply, for the message.
    """
    require(set(item) >= {107, 108, 207}, f"Missing 202 fields {identifier}")
    require(len(item[107]) == UINT32_BYTES, "Reference width differs")
    require(
        item[108] == STREAM_BYTES.to_bytes(UINT32_BYTES, "big"), "Stream size differs"
    )
    require(item[207] == FORK_BYTES.to_bytes(UINT32_BYTES, "big"), "Fork size differs")


def _queue_position(item: dict[int, bytes], identifier: int) -> int:
    """Return the positive queue position of a queued reply.

    Parameters
    ----------
    item : dict[int, bytes]
        The decoded fields of the reply.
    identifier : int
        The transaction identifier of the reply, for the message.

    Returns
    -------
    int
        The queue position carried in field 116.
    """
    require(
        FIELD_QUEUE_POSITION in item
        and int.from_bytes(item[FIELD_QUEUE_POSITION], "big") > 0,
        f"Missing positive queue position {identifier}",
    )
    return int.from_bytes(item[FIELD_QUEUE_POSITION], "big")


def check_references(report: dict, admitted: list[int], queued: list[int]) -> dict:
    """Check the transfer references of the admitted and queued 202 replies.

    Parameters
    ----------
    report : dict
        The verified report.
    admitted : list[int]
        The identifiers of the replies that must carry no queue position.
    queued : list[int]
        The identifiers of the replies that must carry a positive queue position.

    Returns
    -------
    dict
        The hexadecimal references in request order, and the queue positions of
        the queued replies.
    """
    refs = []
    positions = []
    for identifier in admitted + queued:
        item = values(reply(report, identifier))
        _check_transfer_fields(item, identifier)
        if identifier in admitted:
            require(
                FIELD_QUEUE_POSITION not in item, f"Admitted {identifier} was queued"
            )
        else:
            positions.append(_queue_position(item, identifier))
        refs.append(item[107].hex())
    require(len(refs) == len(set(refs)), "Duplicate transfer reference")
    return {"references": refs, "waiting_positions": positions}


def _sent_requests(report: dict, command: int, identifier: int) -> list[bytes]:
    """Return the raw connection-a sends of ``command`` with ``identifier``.

    Parameters
    ----------
    report : dict
        The verified report, with its ``events``.
    command : int
        The transaction type to match.
    identifier : int
        The transaction identifier to match.

    Returns
    -------
    list[bytes]
        The matching frames, in event order.
    """
    return [
        bytes.fromhex(event["hex"])
        for event in report["events"]
        if event["event"] == "send"
        and event["connection"] == "a"
        and int.from_bytes(bytes.fromhex(event["hex"])[TYPE_SLICE], "big") == command
        and int.from_bytes(bytes.fromhex(event["hex"])[IDENTIFIER_SLICE], "big")
        == identifier
    ]


def check_diagnostic(report: dict, identifier: int, uid: bytes) -> dict:
    """Check the 303 reply at ``identifier`` and the target of its request.

    Parameters
    ----------
    report : dict
        The verified report.
    identifier : int
        The transaction identifier of the 303 request and reply.
    uid : bytes
        The account identifier that the request must target.

    Returns
    -------
    dict
        The length of field 101, and the hexadecimal values of fields 101 and 102.
    """
    item = values(reply(report, identifier))
    require(set(item) == {101, 102}, f"303 fields differ at {identifier}")
    require(item[102] == b"framing-fixture", "303 name differs")
    require(item[101].startswith(b"Nickname:"), "303 text prefix differs")
    requests = _sent_requests(report, DIAGNOSTIC_TYPE, identifier)
    require(
        len(requests) == 1 and requests[0].endswith(b"\x00g\x00\x02" + uid),
        "303 target differs from current roster",
    )
    return {
        "field101_bytes": len(item[101]),
        "field101_hex": item[101].hex(),
        "field102_hex": item[102].hex(),
    }


def check_cancellations(report: dict, targets: dict[int, bytes]) -> None:
    """Check that each 214 cancellation names the reference it was given.

    Parameters
    ----------
    report : dict
        The verified report.
    targets : dict[int, bytes]
        The expected reference of each cancelled transaction identifier.
    """
    for identifier, expected_ref in targets.items():
        reply(report, identifier)
        sent = _sent_requests(report, TYPE_REFERENCE_CLEANUP, identifier)
        require(len(sent) == 1, f"Missing unique 214 send {identifier}")
        request = decode_frame(sent[0])
        require(
            values(request) == {107: expected_ref},
            f"Cancellation {identifier} targeted another reference",
        )
