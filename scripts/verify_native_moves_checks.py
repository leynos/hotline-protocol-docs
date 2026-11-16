"""Check the replies of each native move and Trash deletion case.

verify_native_moves imports move and deletion from this module, and the names
below stay importable from verify_native_moves for its consumers.
"""

import dataclasses as dc
import typing as typ

from native_move_cases import COMMENT
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
from verify_native_mkdir import listing
from verify_native_shx import fields

__all__ = [
    "ACCESS_BYTES",
    "FAILED_MOVES",
    "MoveListings",
    "deletion",
    "move",
]

type Report = dict[str, typ.Any]
type Spec = dict[str, typ.Any]
type Listing = dict[bytes, typ.Any]

# The privilege bitmap of a low account is eight zero bytes.
ACCESS_BYTES = 8
# The fields of a file-information reply that the move and alias checks compare.
FIELD_KIND = 205  # the kind text, which the alias check compares
FIELD_COMMENT = 210  # the comment, which the alias check compares
# The logical size, in two bytes, that the alias reports for its moved target.
TRASHED_TARGET_SIZE = 332
# The cases whose move is refused, or whose source does not move.
FAILED_MOVES = {
    "file-collision",
    "folder-collision",
    "missing-source",
    "missing-destination",
    "destination-file",
    "low-permission",
    "own-child",
    "own-self",
}


@dc.dataclass(frozen=True, slots=True)
class MoveListings:
    """The source and destination listings read before and after one move."""

    before: Listing
    destination: Listing
    after: Listing
    new_destination: Listing


def _expected_move_error(spec: Spec, name: bytes) -> bytes | None:
    """Name the error that a move case must return, or ``None`` when it succeeds.

    Parameters
    ----------
    spec : dict[str, typing.Any]
        The description of the move case.
    name : bytes
        The name of the moved entry.

    Returns
    -------
    bytes | None
        The expected error text, or ``None`` when the move succeeds.
    """
    match spec["label"]:
        case "missing-source":
            return (
                b"Cannot move because there is no file/folder named \xd2"
                + name
                + b"\xd3."
            )
        case "missing-destination" | "destination-file":
            return (
                b"Cannot move \xd2"
                + name
                + b"\xd3 because the destination folder could not be found."
            )
        case "file-collision" | "folder-collision":
            return (
                b"Cannot move \xd2"
                + name
                + b"\xd3 because there is already a file/folder in the destination "
                b"folder with the same name."
            )
        case "low-permission":
            return b"You are not allowed to move " + (
                b"folders." if spec["folder"] else b"files."
            )
        case "own-child" | "own-self":
            return (
                b"Cannot move \xd2"
                + name
                + b"\xd3 into itself or into a subfolder of itself."
            )
        case _:
            return None


def _check_moved(report: Report, name: bytes, listings: MoveListings) -> None:
    """Check the listings and the names of a move that changed the location.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report of the case.
    name : bytes
        The name of the moved entry.
    listings : MoveListings
        The listings read before and after the move.
    """
    before, destination = listings.before, listings.destination
    after, new_destination = listings.after, listings.new_destination
    require(
        name in before
        and name not in destination
        and set(after) == set(before) - {name}
        and set(new_destination) == set(destination) | {name},
        "Move did not remove/add exact source entry",
    )
    require(
        new_destination[name] == before[name],
        "Move changed listing metadata/name bytes",
    )
    require(
        reply(report, 22)["error"] == 1 and reply(report, 23)["error"] == 0,
        "Moved old/new name resolution differs",
    )
    old_info, new_info = fields(reply(report, 12)), fields(reply(report, 23))
    require(
        all(
            old_info.get(k) == new_info.get(k)
            for k in [
                FIELD_FILE_NAME,
                FIELD_KIND,
                FIELD_FILE_CREATOR,
                FIELD_FILE_SIZE,
                FIELD_COMMENT,
                FIELD_FILE_TYPE,
            ]
        ),
        "Move changed exposed metadata",
    )


def _check_rejected(report: Report, label: str, listings: MoveListings) -> None:
    """Check that a move that did not change the location left the listings alone.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report of the case.
    label : str
        The case label, which decides the expected source resolution.
    listings : MoveListings
        The listings read before and after the move.
    """
    require(
        listings.before == listings.after
        and listings.destination == listings.new_destination,
        "Failed/same-parent move changed a listing",
    )
    require(
        reply(report, 22)["error"] == (1 if label == "missing-source" else 0),
        "Rejected move source resolution differs",
    )


def move(report: Report, spec: Spec) -> dict[str, typ.Any]:
    """Check the replies of one move case and report what it did.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report of the case.
    spec : dict[str, typing.Any]
        The description of the case from ``move_specs``.

    Returns
    -------
    dict[str, typing.Any]
        The case, whether it returned an error and whether its entry changed place.
    """
    name, label = bytes.fromhex(spec["name_hex"]), spec["label"]
    expected_error = _expected_move_error(spec, name)
    ack = reply(report, 13)
    require(
        ack["error"] == (1 if expected_error else 0)
        and fields(ack)
        == ({FIELD_ERROR_TEXT: expected_error} if expected_error else {}),
        "Move ACK/error differs",
    )
    access = next(
        f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access)
        == {
            FIELD_ACCESS_BITMAP: bytes(ACCESS_BYTES) if spec["role"] == "low" else ADMIN
        },
        "Move privilege bitmap differs",
    )
    listings = MoveListings(
        before=listing(reply(report, 10)),
        destination=listing(reply(report, 11)),
        after=listing(reply(report, 20)),
        new_destination=listing(reply(report, 21)),
    )
    changed = label not in FAILED_MOVES | {"same-parent"}
    if changed:
        _check_moved(report, name, listings)
    else:
        _check_rejected(report, label, listings)
    require(
        all(listings.after[k] == v for k, v in listings.before.items() if k != name),
        "Move changed unrelated source entry",
    )
    require(
        all(
            listings.new_destination[k] == v
            for k, v in listings.destination.items()
            if k != name
        ),
        "Move changed unrelated destination entry",
    )
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Move control lost liveness",
    )
    return {
        "case": spec["case"],
        "error": expected_error is not None,
        "changed_location": changed,
    }


def _expected_delete_error(label: str) -> bytes | None:
    """Name the error that a deletion case must return, or ``None`` when it succeeds.

    Parameters
    ----------
    label : str
        The deletion case.

    Returns
    -------
    bytes | None
        The expected error text, or ``None`` when the deletion succeeds.
    """
    match label:
        case "missing-source":
            return (
                b"Cannot delete \xd2no-such-delete\xd3 because it does not exist or "
                b"cannot be found."
            )
        case "denied-file" | "denied-directory":
            return b"You are not allowed to delete " + (
                b"folders." if label.endswith("directory") else b"files."
            )
        case _:
            return None


def _check_deleted(
    report: Report,
    name: bytes,
    error: bytes | None,
    listings: tuple[Listing, Listing],
) -> None:
    """Check the listings of a deletion, which must change only when it succeeds.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report of the case.
    name : bytes
        The name of the deleted entry.
    error : bytes | None
        The expected error text, or ``None`` when the deletion succeeds.
    listings : tuple[dict[bytes, typing.Any], dict[bytes, typing.Any]]
        The listing before the deletion and the listing after it.
    """
    before, after = listings
    if error:
        require(before == after, "Rejected delete changed listing")
    else:
        require(
            name in before and set(after) == set(before) - {name},
            "Delete did not remove exactly the owned entry",
        )
        require(
            all(after[k] == v for k, v in before.items() if k != name),
            "Delete changed another listing record",
        )
        require(
            reply(report, 21)["error"] == 1,
            "Deleted source still resolves through original path",
        )


def _check_alias_trash(report: Report) -> None:
    """Check that the alias still resolves to its target after the target is trashed.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report of the alias case.
    """
    values = fields(reply(report, 30))
    require(
        reply(report, 30)["error"] == 0
        and values[FIELD_KIND] == b"TEXT (alias)"
        and values[FIELD_FILE_SIZE] == TRASHED_TARGET_SIZE.to_bytes(2, "big")
        and values[FIELD_COMMENT] == COMMENT,
        "Alias no longer resolves target moved to Trash",
    )


def deletion(report: Report, spec: Spec) -> dict[str, typ.Any]:
    """Check the replies of one deletion case and report what it did.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report of the case.
    spec : dict[str, typing.Any]
        The description of the case from ``deletion_specs``.

    Returns
    -------
    dict[str, typing.Any]
        The case and whether it returned an error.
    """
    label = spec["case"]
    name = (
        b"del-path-only"
        if spec["name_hex"] is None
        else bytes.fromhex(spec["name_hex"])
    )
    error = _expected_delete_error(label)
    ack = reply(report, 12)
    require(
        ack["error"] == (1 if error else 0)
        and fields(ack) == ({FIELD_ERROR_TEXT: error} if error else {}),
        "Delete ACK/error differs",
    )
    listings = (listing(reply(report, 10)), listing(reply(report, 20)))
    _check_deleted(report, name, error, listings)
    if label == "alias-target-to-trash":
        _check_alias_trash(report)
    access = next(
        f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access)
        == {
            FIELD_ACCESS_BITMAP: bytes(ACCESS_BYTES) if spec["role"] == "low" else ADMIN
        },
        "Delete privilege bitmap differs",
    )
    require(reply(report, 90)["error"] == 0, "Delete control lost liveness")
    return {"case": label, "error": error is not None}
