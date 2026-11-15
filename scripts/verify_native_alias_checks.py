"""Check one native alias report against its plan, field by field."""

import typing as typ

from native_alias_cases import DATA
from native_filp import decode
from native_transfer_cases import resource_fork
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]
type Listing = dict[bytes, bytes]

# Cases whose creation is refused, rather than acknowledged.
FAILURES = {
    "missing-source",
    "missing-destination",
    "destination-not-directory",
    "directory-collision",
    "permission-new",
    "permission-conflict",
}
PERMISSION_MESSAGE = b"You are not allowed to make aliases."
MISSING_SOURCE_MESSAGE = (
    b"Cannot make alias because there is no file/folder named \xd2missing\xd3."
)
NO_DESTINATION_MESSAGE = (
    b"Cannot make alias of \xd2file\xd3 because the destination folder could not "
    b"be found."
)
DIRECTORY_COLLISION_MESSAGE = (
    b"Cannot make alias of \xd2dir\xd3 because there is already a file/folder in "
    b"the destination folder with the same name."
)
DATE_BYTES = 8  # the width of each date field
REFERENCE_BYTES = 4  # the width of a transfer reference
FOLDER_LEAF = b"leaf"  # the last name in the folder that the download carries
QUIET_SECONDS = 3  # the quiet interval the plan asks for
QUIET_NANOSECONDS = 3_000_000_000  # the same interval, measured in nanoseconds


def file_metadata(label: str) -> dict[int, bytes]:
    """Name the fields of an ordinary or alias file, besides its name.

    Returns
    -------
    dict[int, bytes]
        The expected field values, in their checked order.
    """
    ordinary = label in {"ordinary-file", "empty-file"}
    expected = {
        205: b"Text File" if ordinary else b"TEXT (alias)",
        206: b"MOTH",
        213: b"TEXT",
        207: b"\0\0" if label == "empty-file" else b"\x01M",
    }
    if label != "empty-file":
        expected[210] = b"alias-comment"
    return expected


def labelled_metadata(label: str) -> dict[int, bytes]:
    """Name the fields that each kind of labelled case must show, besides its name.

    Returns
    -------
    dict[int, bytes]
        The expected field values, in their checked order.
    """
    match label:
        case "self-after-create":
            return {205: b"Unattached Alias", 206: b"n/a", 213: b"alis"}
        case _ if "directory" in label:
            return {
                205: b"Folder" if label == "ordinary-directory" else b"Folder Alias",
                206: b"n/a",
                213: b"fldr",
            }
        case "zero-tags":
            return {205: bytes(4), 206: bytes(4), 213: bytes(4), 207: b"\0\x09"}
        case "unknown-tags":
            return {
                205: b"XxYz",
                206: b"ZzQq",
                213: b"XxYz",
                207: b"\0\x0c",
                210: b"unknown-comment",
            }
        case _:
            return file_metadata(label)


def metadata(report: Report, label: str, name: bytes) -> dict[int, bytes]:
    """Assert field presence as well as bytes; zero tags are present values.

    Returns
    -------
    dict[int, bytes]
        The fields of the information reply.
    """
    actual = fields(reply(report, 10))
    expected = {201: name} | labelled_metadata(label)
    dates = set() if label == "self-after-create" else {208, 209}
    require(set(actual) == set(expected) | dates, f"{label}: metadata presence differs")
    require(
        all(actual[k] == v for k, v in expected.items()),
        f"{label}: metadata bytes differ",
    )
    require(
        all(
            len(actual[k]) == DATE_BYTES and actual[k] != bytes(DATE_BYTES)
            for k in dates
        ),
        "Metadata date width/value differs",
    )
    return actual


def rejection_message(label: str) -> bytes:
    """Name the error that the server must return for a refused creation.

    Returns
    -------
    bytes
        The exact error text.
    """
    if label.startswith("permission"):
        return PERMISSION_MESSAGE
    if label == "missing-source":
        return MISSING_SOURCE_MESSAGE
    if label in {"missing-destination", "destination-not-directory"}:
        return NO_DESTINATION_MESSAGE
    return DIRECTORY_COLLISION_MESSAGE


def check_rejection(
    label: str, response: Report, before: Listing, after: Listing
) -> None:
    """Check that a refused creation returns its error and changes nothing."""
    require(
        response["error"] == 1 and fields(response) == {100: rejection_message(label)},
        "Alias error outcome differs",
    )
    require(before == after, "Rejected alias changed the visible directory")


def check_acceptance(
    expected: Report, response: Report, before: Listing, after: Listing
) -> None:
    """Check that an accepted creation adds, or replaces, only its own entry."""
    require(response["error"] == 0 and fields(response) == {}, "Alias ACK differs")
    target = bytes.fromhex(expected["target_hex"])
    require(target in after, "Alias target name differs")
    if expected["case"] in {"file-collision", "same-location"}:
        require(
            set(before) == set(after) and before[target] != after[target],
            "Alias replacement effect differs",
        )
    else:
        require(
            set(after) - set(before) == {target} and set(before) <= set(after),
            "Alias addition differs",
        )
    require(
        all(after[k] == v for k, v in before.items() if k != target),
        "Alias changed unrelated entry",
    )


def creation(report: Report, expected: Report) -> None:
    """Check the privilege, the outcome and the listings of one alias creation."""
    label = expected["case"]
    before, after = listing(reply(report, 10)), listing(reply(report, 14))
    response = reply(report, 12)
    privileges = bytes(8) if expected["role"] == "low" else ADMIN
    require(
        fields(report["frames"][1]) == {110: privileges},
        "Alias privilege control differs",
    )
    if label in FAILURES:
        check_rejection(label, response, before, after)
    else:
        check_acceptance(expected, response, before, after)
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Alias control lost liveness",
    )


def folder_payload(value: bytes) -> bytes:
    """Check the descriptor and length framing of a folder download.

    Returns
    -------
    bytes
        The complete FILP stream that the folder carries.
    """
    # Descriptor length, descriptor bytes, FILP length, then complete FILP.
    length = int.from_bytes(value[:2], "big")
    descriptor = value[2 : 2 + length]
    require(descriptor[-4:] == FOLDER_LEAF, "Alias directory leaf differs")
    offset = 2 + length
    size = int.from_bytes(value[offset : offset + 4], "big")
    value = value[offset + 4 :]
    require(len(value) == size, "Alias folder transfer length differs")
    return value


def file_payload(report: Report, value: bytes, ack: dict[int, bytes]) -> bytes:
    """Check the advertised length and the cancellation of a file download.

    Returns
    -------
    bytes
        The FILP stream that the file carries.
    """
    require(
        len(value) == int.from_bytes(ack[108], "big"),
        "Alias transfer advertised length differs",
    )
    require(
        reply(report, 11)["error"] == 0 and fields(reply(report, 11)) == {},
        "Alias cancellation ACK differs",
    )
    return value


def check_forks(forks: dict[str, bytes], *, folder: bool, collision: bool) -> None:
    """Check the resolved data, resource and name forks of a download."""
    require(
        forks["DATA"]
        == (b"dir-leaf" if folder else b"same-source" if collision else DATA),
        "Alias resolved data fork differs",
    )
    require(
        forks["MACR"] == (b"" if folder or collision else resource_fork()),
        "Alias resolved resource fork differs",
    )
    info = forks["INFO"]
    n = int.from_bytes(info[70:72], "big")
    require(
        info[72 : 72 + n] == (b"leaf" if folder else b"same" if collision else b"file"),
        "Alias FILP resolved name differs",
    )


def download(report: Report, *, folder: bool = False, collision: bool = False) -> None:
    """Check the reference, the payload and the forks of one alias download."""
    ack = fields(reply(report, 10))
    require(
        reply(report, 10)["error"] == 0 and len(ack[107]) == REFERENCE_BYTES,
        "Alias download reference differs",
    )
    value = bytes.fromhex(report["streams"]["transfer"]["received_hex"])
    value = folder_payload(value) if folder else file_payload(report, value, ack)
    check_forks(decode(value), folder=folder, collision=collision)
    require(reply(report, 90)["error"] == 0, "Alias transfer control lost liveness")


def listing_views(reports: dict[str, Report]) -> None:
    """Pin observed native enumeration sequences, without inventing a comparator."""
    root = listing(reply(reports["info/ordinary-file"], 11))
    require(
        list(root)
        == [
            b"A",
            b"B",
            b"C",
            b"D",
            b"dir",
            b"empty",
            b"file",
            b"hi-\x9a",
            b"m-al20-absent",
            b"m-al20-empty",
            b"m-al20-zero",
            b"same",
            b"self",
            b"unknown-tags",
            b"zero-tags",
        ],
        "Native root listing order/name bytes differ",
    )
    require(
        root[b"file"][:16] == b"TEXTMOTH" + (333).to_bytes(4, "big") + bytes(4),
        "File listing does not sum both forks",
    )
    require(
        root[b"self"][:16] == b"alis" + bytes(12), "Unattached alias listing differs"
    )
    require(
        root[b"dir"][:16] == b"fldr" + bytes(4) + (1).to_bytes(4, "big") + bytes(4),
        "Directory listing valence differs",
    )
    require(
        root[b"zero-tags"][:16] == bytes(8) + (9).to_bytes(4, "big") + bytes(4),
        "Zero-tag listing differs",
    )
    require(
        not listing(reply(reports["create/live-file"], 10)),
        "Empty directory representation differs",
    )
    for key in ["info/file-alias", "info/file-chain"]:
        alias = listing(reply(reports[key], 11))
        require(
            list(alias) == [b"dir", b"file"]
            and alias[b"file"] == root[b"file"]
            and alias[b"dir"] == root[b"dir"],
            "Alias listing exposes physical fork/tag or different ordering",
        )
    derived = listing(reply(reports["info/derived-alias"], 11))
    require(
        list(derived)
        == [b"derived-dir", b"derived-empty", b"derived-link", b"hi-\x9a"],
        "Derived alias listing order differs",
    )
    collision = listing(reply(reports["create/file-collision"], 14))[b"same"]
    require(
        collision[:16] == b"TEXTMOTH" + (11).to_bytes(4, "big") + bytes(4),
        "Collision alias listing uses physical destination size",
    )


def transfer_quiet(report: Report, plan: Report) -> None:
    """Check that each quiet step of the plan was observed for long enough."""
    for action, step in enumerate(plan["steps"]):
        if step["op"] != "expect_quiet":
            continue
        require(
            step["timeout"] == QUIET_SECONDS, "Alias transfer quiet interval differs"
        )
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
            "Alias transfer quiet observation missing/short",
        )
