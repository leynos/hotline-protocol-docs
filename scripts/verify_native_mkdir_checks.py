"""Check the creation, empty-root and upload effects of a native mkdir corpus."""

import typing as typ

from native_transfer_cases import file_stream
from native_wire_names import (
    FIELD_FILE_ENTRY,
    FIELD_TRANSFER_REFERENCE,
    FILE_ENTRY_HEADER_BYTES,
    FILE_ENTRY_NAME_LENGTH_START,
)
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Listing = dict[bytes, bytes]

# The creation cases that the native server refuses.
FAILURES = {
    "existing-directory",
    "existing-file",
    "case-collision",
    "name-absent",
    "name-empty",
    "parent-file",
    "parent-missing",
    "low-permission-new",
    "low-permission-conflict",
}
CREATE_IDENTIFIER = 11  # the request identifier of the creation under test
TRANSFER_REFERENCE_BYTES = 4  # the four bytes of a transfer reference
QUIET_NANOSECONDS = 1_000_000_000  # the bounded one-second quiet interval
SPECIAL_COMPONENTS = {
    "path-dot-component",
    "path-dotdot-component",
    "path-colon-component",
    "path-high-component",
    "path-nul-component",
}


def listing(frame: Report) -> Listing:
    """Decode the file-list entries of a listing reply, keyed by name.

    Returns
    -------
    dict[bytes, bytes]
        The whole record of each entry, keyed by the entry's name bytes.
    """
    require(
        frame["is_reply"] == 1 and frame["type"] == 0 and frame["error"] == 0,
        "Listing failed",
    )
    result = {}
    for record in frame["fields"]:
        value = bytes.fromhex(record["hex"])
        require(
            record["id"] == FIELD_FILE_ENTRY
            and len(value) >= FILE_ENTRY_HEADER_BYTES
            and int.from_bytes(
                value[FILE_ENTRY_NAME_LENGTH_START:FILE_ENTRY_HEADER_BYTES], "big"
            )
            == len(value) - FILE_ENTRY_HEADER_BYTES
            and value[12:16] == bytes(4),
            "File-list record grammar differs",
        )
        name = value[FILE_ENTRY_HEADER_BYTES:]
        require(name not in result, "Repeated file-list name")
        result[name] = value
    return result


def created_name(expected: Report) -> bytes:
    """Derive the name that a successful creation of ``expected`` must add.

    Returns
    -------
    bytes
        The name bytes that the native server records for the new folder.
    """
    label = expected["case"]
    if label == "path-supplies-name":
        return b"via-path"
    if label == "empty-name-path-supplies":
        return b"via-empty"
    value = bytes.fromhex(expected["name_hex"])
    if label == "long-extension":
        return value[:27] + b".txt"
    return value[:31].replace(b":", b"-")


def check_bootstrap(frames: list[Report], expected: Report, agreement: bytes) -> None:
    """Check the frame sequence, the bootstrap and the permission control."""
    require(
        [(f["type"], f["is_reply"], f["id"]) for f in frames]
        == [
            (0, 1, 1),
            (354, 0, 1),
            (109, 0, 2),
            (0, 1, 10),
            (0, 1, 11),
            (0, 1, 12),
            (0, 1, 90),
        ],
        "Creation response sequence differs",
    )
    require(
        fields(frames[0]) == {160: b"\0\xbe", 161: bytes(2)}
        and fields(frames[2]) == {101: agreement},
        "Creation bootstrap changed",
    )
    privileges = bytes(8) if expected["role"] == "low" else ADMIN
    require(
        fields(frames[1]) == {110: privileges}, "Creation permission control differs"
    )
    require(
        all(f["error"] == 0 for f in frames if f["id"] != CREATE_IDENTIFIER),
        "Creation control failed",
    )


def failure_message(expected: Report) -> bytes:
    """Build the refusal text that a failed creation of ``expected`` must carry.

    Returns
    -------
    bytes
        The error text of the creation reply.
    """
    if expected["role"] == "low":
        return b"You are not allowed to create folders."
    name = bytes.fromhex(expected["name_hex"] or "")
    suffix = (
        b"the enclosing folder could not be found."
        if expected["case"] in {"parent-file", "parent-missing"}
        else b"there is already a file or folder with that name."
    )
    return b"Cannot create folder \xd2" + name + b"\xd3 because " + suffix


def check_failure(
    response: Report, before: Listing, after: Listing, expected: Report
) -> None:
    """Check that a refused creation returned its error and changed nothing."""
    message = failure_message(expected)
    require(
        response["error"] == 1 and fields(response) == {100: message},
        "Creation error outcome differs",
    )
    require(after == before, "Failed creation changed the visible directory")


def check_success(
    response: Report, before: Listing, after: Listing, expected: Report
) -> bytes:
    """Check that a successful creation added exactly its one folder.

    Returns
    -------
    bytes
        The name bytes of the folder that the creation added.
    """
    added = created_name(expected)
    require(
        response["error"] == 0 and fields(response) == {},
        "Successful create ACK differs",
    )
    require(
        set(after) - set(before) == {added} and not (set(before) - set(after)),
        "Creation target or name bytes differ",
    )
    require(
        all(after[k] == v for k, v in before.items()),
        "Creation altered another listing record",
    )
    value = after[added]
    require(value[:16] == b"fldr" + bytes(12), "New directory record differs")
    return added


def check_creation(report: Report, expected: Report, agreement: bytes) -> Report:
    """Check one creation capture and summarise its listings and outcome.

    Returns
    -------
    dict[str, typing.Any]
        The case, the reply status, the added name and both listings as hex.
    """
    frames = report["frames"]
    check_bootstrap(frames, expected, agreement)
    before, after = listing(reply(report, 10)), listing(reply(report, 12))
    response = reply(report, 11)
    label = expected["case"]
    if label in FAILURES:
        check_failure(response, before, after, expected)
        added = None
    else:
        added = check_success(response, before, after, expected)
    require(fields(reply(report, 90)) == {}, "Creation liveness ACK differs")
    if label in SPECIAL_COMPONENTS:
        require(
            not before, "Special component did not address its literal empty directory"
        )
    return {
        "case": label,
        "status": response["error"],
        "added_name_hex": None if added is None else added.hex(),
        "before_names_hex": [n.hex() for n in before],
        "after_names_hex": [n.hex() for n in after],
    }


def creation_quiet(report: Report, plan: Report) -> None:
    """Check only the explicitly bounded one-second post-liveness observation."""
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "expect_quiet":
            continue
        require(step["timeout"] == 1, "Unexpected creation quiet interval")
        observations = [
            e
            for e in report["events"]
            if e["action"] == action and e["event"] == "quiet"
        ]
        previous = [e for e in report["events"] if e["action"] < action]
        require(
            len(observations) == 1
            and bool(previous)
            and observations[0]["elapsed_ns"] - previous[-1]["elapsed_ns"]
            >= QUIET_NANOSECONDS,
            "Missing or short creation quiet observation",
        )


def check_root_empty(report: Report, initial: Listing) -> None:
    """Check the empty-root matrix: refused creations and unchanged inputs."""
    message = (
        b"Cannot create folder \xd2\xd3 because "
        b"there is already a file or folder with that name."
    )
    require(
        [f["id"] for f in report["frames"] if f["is_reply"]]
        == [1, 10, 20, 21, 22, 23, 24, 25, 90, 91],
        "Empty-root matrix shape differs",
    )
    for identifier in range(20, 26):
        frame = reply(report, identifier)
        require(
            frame["error"] == 1 and fields(frame) == {100: message},
            "Empty-root creation outcome differs",
        )
    require(
        listing(reply(report, 10)) == listing(reply(report, 90)) == initial
        and reply(report, 91)["error"] == 0
        and fields(reply(report, 91)) == {},
        "Empty-root inputs changed Files or lost liveness",
    )


def uploaded(report: Report, data: bytes) -> None:
    """Check the native setup upload that carried ``data``."""
    values = fields(
        next(
            f
            for f in report["frames"]
            if f["is_reply"]
            and any(v["id"] == FIELD_TRANSFER_REFERENCE for v in f["fields"])
        )
    )
    reference = values[FIELD_TRANSFER_REFERENCE]
    require(
        len(reference) == TRANSFER_REFERENCE_BYTES
        and int.from_bytes(reference, "big") != 0,
        "Missing native upload reference",
    )
    body = file_stream(data, b"")
    require(
        report["streams"]["upload"]["sent_hex"]
        == (b"HTXF" + reference + len(body).to_bytes(4, "big") + bytes(4) + body).hex()
        and report["streams"]["upload"]["received_hex"] == "",  # pylint: disable=use-implicit-booleaness-not-comparison-to-string  # == "" rejects a non-string value that "not" would accept
        "Native setup upload bytes differ",
    )
