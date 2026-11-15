"""Check the observations of one native metadata case.

The file-info reply of an entry, the account write with its errors, its old and
new names and listings, and the comment-size boundaries. Each check reads the
replies in the same order as the corpus was first verified.
"""

import typing as typ

from native_metadata_cases import ACCOUNTS, final_name
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_FILE_CREATOR,
    FIELD_FILE_NAME,
    FIELD_FILE_SIZE,
    FIELD_FILE_TYPE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_fork_support import DATE_BYTES, FIELD_FILE_COMMENT, FILE_DATE_FIELDS
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]

# The entry's kind string: protocol.md, "Creating a New Folder", notes that
# fields 205 and 206 can be descriptive strings and are not a fixed schema.
FIELD_DESCRIPTION = 205
COMMENT_READBACK_LIMIT = 199  # a comment readback returned at most this many bytes
COMMENT_BOUNDARY_SIZES = [0, 1, 198, 199, 200, 201, 254, 255, 256, 300, 65535]
FIRST_BOUNDARY_ID = 100
LISTING_PREFIX_BYTES = 16  # the type, creator and size fields of a listing entry
LENGTH_BYTES = 4


def expected_comment(spec: Report) -> bytes | None:
    """Return the comment that a table row must leave on its entry.

    Returns
    -------
    bytes | None
        The base comment for an unchanged comment, ``None`` when cleared, and
        otherwise the value read back, truncated to the readback limit.
    """
    value = spec["comment_hex"]
    if value is None or spec["role"] in {"rename", "neither"}:
        return b"base-comment"
    value = bytes.fromhex(value)
    return None if value in {b"", b"\0"} else value[:COMMENT_READBACK_LIMIT]


def info(
    frame: Report,
    name: bytes,
    folder: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    comment: bytes | None,
) -> None:
    """Check the final file-info reply of an entry, file or folder."""
    require(frame["error"] == 0, "Expected final metadata failed")
    actual = fields(frame)
    expected = {
        FIELD_FILE_NAME: name,
        FIELD_DESCRIPTION: b"Folder" if folder else b"Text File",
        FIELD_FILE_CREATOR: b"n/a" if folder else b"MOTH",
        FIELD_FILE_TYPE: b"fldr" if folder else b"TEXT",
    }
    if not folder:
        expected[FIELD_FILE_SIZE] = b"\0\r"
    if comment is not None:
        expected[FIELD_FILE_COMMENT] = comment
    require(
        set(actual) == set(expected) | set(FILE_DATE_FIELDS),
        "Metadata presence differs",
    )
    require(
        all(actual[k] == v for k, v in expected.items()),
        "Metadata name/comment/type bytes differ",
    )
    require(
        all(len(actual[k]) == DATE_BYTES for k in FILE_DATE_FIELDS),
        "Metadata date width differs",
    )


def check_access(report: Report, role: str) -> None:
    """Check the privilege bitmap that the login of the case's account reports."""
    access = next(
        f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access)
        == {FIELD_ACCESS_BITMAP: ADMIN if role == "admin" else ACCOUNTS[role][1]},
        "Mutation privilege bitmap differs",
    )


def mutation_error(spec: Report) -> bytes | None:
    """Name the error that the account write of a row must report, if any.

    Returns
    -------
    bytes | None
        The conflict, the denied comment or the denied rename text, or ``None``
        when the write is allowed.
    """
    name = bytes.fromhex(spec["name_hex"])
    noun = b"folders" if spec["folder"] else b"files"
    role = spec["role"]
    if spec["case"].endswith("comment-before-conflict"):
        return (
            b"Cannot set info for \xd2"
            + name
            + (
                b"\xd3:\rA file or folder with the specified name already exists."
                b"\rID 4/115 [-48]"
            )
        )
    if role in {"rename", "neither"} and spec["comment_hex"] is not None:
        return b"You are not allowed set comments for " + noun + b"."
    if role == "comment" and spec["new_hex"] is not None:
        return b"You are not allowed to rename " + noun + b"."
    return None


def check_rename_result(report: Report, spec: Report) -> None:
    """Check the old name, the new name and the comment after the write."""
    name, new = bytes.fromhex(spec["name_hex"]), final_name(spec)
    folder = spec["folder"]
    if new != name:
        old = reply(report, 20)
        require(
            old["error"] == 1
            and fields(old)
            == {
                FIELD_ERROR_TEXT: b"Cannot get info because there is no file/folder "
                b"named \xd2" + name + b"\xd3."
            },
            "Old name still resolves after rename",
        )
    else:
        info(reply(report, 20), name, folder, expected_comment(spec))
    if new != name or spec["new_hex"] in {None, "", spec["name_hex"]}:
        info(reply(report, 21), new, folder, expected_comment(spec))
    elif spec["case"].endswith("comment-before-conflict"):
        info(reply(report, 21), b"occupied", folder=False, comment=b"base-comment")
    else:
        require(
            reply(report, 21)["error"] == 1,
            "Denied rename unexpectedly created destination",
        )


def check_listing(report: Report, spec: Report) -> None:
    """Check that a rename changed only the owned entry in the listing."""
    name, new = bytes.fromhex(spec["name_hex"]), final_name(spec)
    before, after = listing(reply(report, 11)), listing(reply(report, 22))
    if new != name:
        require(
            set(after) == (set(before) - {name}) | {new},
            "Rename listing effect differs",
        )
        require(
            after[new]
            == before[name][:LISTING_PREFIX_BYTES]
            + len(new).to_bytes(LENGTH_BYTES, "big")
            + new,
            "Rename changed size/type or name grammar",
        )
    else:
        require(before == after, "Comment/no-op/rejected rename changed listing")
    require(
        all(after[k] == v for k, v in before.items() if k != name),
        "Mutation changed another listing entry",
    )


def mutation(report: Report, spec: Report) -> Report:
    """Check one account-write case and summarise what it observed.

    Returns
    -------
    dict[str, typing.Any]
        The case name, whether it returned an error, whether it renamed the
        entry, and the comment that it should leave, in hexadecimal.
    """
    name, new = bytes.fromhex(spec["name_hex"]), final_name(spec)
    info(reply(report, 10), name, spec["folder"], b"base-comment")
    check_access(report, spec["role"])
    ack = reply(report, 12)
    error = mutation_error(spec)
    require(
        ack["error"] == (1 if error else 0)
        and fields(ack) == ({FIELD_ERROR_TEXT: error} if error else {}),
        "Mutation ACK/error differs",
    )
    check_rename_result(report, spec)
    check_listing(report, spec)
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Mutation control lost liveness",
    )
    comment = expected_comment(spec)
    return {
        "case": spec["case"],
        "error": error is not None,
        "renamed": new != name,
        "comment_hex": None if comment is None else comment.hex(),
    }


def comment_boundaries(report: Report) -> None:
    """Check that each comment size reads back at the retained boundary."""
    for index, size in enumerate(COMMENT_BOUNDARY_SIZES):
        identifier = FIRST_BOUNDARY_ID + index * 2
        require(
            reply(report, identifier)["error"] == 0
            and fields(reply(report, identifier)) == {},
            "Boundary write failed",
        )
        values = fields(reply(report, identifier + 1))
        require(
            reply(report, identifier + 1)["error"] == 0
            and values.get(FIELD_FILE_COMMENT)
            == (None if size == 0 else b"x" * min(size, COMMENT_READBACK_LIMIT)),
            "Comment readback boundary differs",
        )
