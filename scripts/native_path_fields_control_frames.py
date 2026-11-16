"""Read and check single frames and views of the 212/325 path matrix.

Part of the path-fields runner (``native_path_fields_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. Each check fails closed with a ``ValueError`` that names what differed.
"""

import collections
import hashlib
import typing as typ

import native_path_fields_cases as cases
from native_news_decode import categories
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_FILE_NAME,
    FIELD_FILE_TYPE,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_account_updates import enumeration
from verify_native_auth import ADMIN, roster
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]

AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
PARENTS = {"S": cases.SOURCE, "wrapper": cases.WRAPPER, "H": cases.HIGH}
MARKERS = {b"p" + bytes([48 + i]) for i in range(6)}
LOGIN_REPLY_FIELDS = {160: b"\0\xbe", 161: b"\0\0"}
FOLDER_KIND = b"fldr"
TYPE_CREATOR_BYTES = 8
NO_TAIL = ""  # the text of a frame that leaves nothing unconsumed


def need(ok: bool, message: str) -> None:  # ruff: ignore[boolean-type-hint-positional-argument]  # called as need(ok, message) throughout
    """Fail closed unless a condition holds.

    Parameters
    ----------
    ok : bool
        The condition.
    message : str
        The message of the failure.

    Raises
    ------
    ValueError
        If the condition is false.
    """
    if not ok:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(raw).hexdigest()


def one(frames: list[Report], connection: str, identifier: int) -> Report:
    """Find the single direct reply of a flow to one request.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    result = [
        f
        for f in frames
        if f["connection"] == connection
        and f["type"] == 0
        and f["is_reply"] == 1
        and f["id"] == identifier
    ]
    need(len(result) == 1, f"Missing/duplicate direct reply {connection}/{identifier}")
    return result[0]


def exact_fields(frame: Report) -> dict[int, bytes]:
    """Read a frame's fields, refusing a malformed, fragmented or repeated one.

    Returns
    -------
    dict[int, bytes]
        The field values by identifier.
    """
    values = fields(frame)
    need(
        frame["flags"] == 0
        and frame["total_size"] == frame["data_size"]
        and frame.get("declared_field_count") == len(frame["fields"])
        and len(values) == len(frame["fields"])
        and frame.get("unconsumed_hex") == NO_TAIL,
        "Malformed/fragmented/repeated scalar frame",
    )
    return values


def success(frame: Report) -> None:
    """Require a frame to be a direct success reply."""
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Expected direct success",
    )


def login_gate(frames: list[Report], connection: str) -> None:
    """Require a flow's login reply, its admin grant and its agreement."""
    ack = one(frames, connection, 1)
    success(ack)
    need(exact_fields(ack) == LOGIN_REPLY_FIELDS, "Login version/extras differ")
    grants = [
        f
        for f in frames
        if f["connection"] == connection and f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    ]
    agreements = [
        f
        for f in frames
        if f["connection"] == connection and f["type"] == TYPE_LOGIN_AGREEMENT
    ]
    need(
        len(grants) == len(agreements) == 1
        and exact_fields(grants[0]) == {FIELD_ACCESS_BITMAP: ADMIN}
        and sha(exact_fields(agreements[0]).get(FIELD_DATA, b"")) == AGREEMENT_SHA,
        "Admin grant/agreement differs",
    )


def file_view(frame: Report) -> list[str]:
    """List the names in a file listing, in hexadecimal.

    Returns
    -------
    list[str]
        The names.
    """
    return [name.hex() for name in listing(frame)]


def file_types(frame: Report) -> dict[str, str]:
    """Map each name in a file listing to its type and creator.

    Returns
    -------
    dict[str, str]
        The type and creator, in hexadecimal, by name in hexadecimal.
    """
    return {
        name.hex(): record[:TYPE_CREATOR_BYTES].hex()
        for name, record in listing(frame).items()
    }


def news_view(frame: Report) -> list[Report]:
    """List the categories in a news reply.

    Returns
    -------
    list[dict[str, typing.Any]]
        One field, kind and name entry per category.
    """
    return [
        {"field": row["field"], "kind": row["kind"], "name_hex": row["name"].hex()}
        for row in categories(frame)
    ]


def file_info(frame: Report, marker: bytes) -> Report:
    """Require a file-info reply to name the owned marker as a folder.

    Returns
    -------
    dict[str, typing.Any]
        The field identifiers, the name and the raw hash of the reply.
    """
    success(frame)
    data = exact_fields(frame)
    need(
        data.get(FIELD_FILE_NAME) == marker
        and data.get(FIELD_FILE_TYPE) == FOLDER_KIND,
        "Owned marker206 name/kind differs",
    )
    return {
        "field_ids": sorted(data),
        "name_hex": marker.hex(),
        "raw_sha256": sha(bytes.fromhex(frame["raw_hex"])),
    }


def check_names(actual: list[str], expected: set[bytes], label: str) -> None:
    """Require a listing to hold exactly the expected names, once each."""
    need(
        set(actual) == {name.hex() for name in expected}
        and len(actual) == len(expected),
        f"{label} owned listing differs",
    )


def location(views: dict[str, list[str]], marker: bytes) -> str | None:
    """Find which selected parent holds a marker.

    Returns
    -------
    str | None
        The parent, or ``None`` when no parent holds it.
    """
    found = [parent for parent, names in views.items() if marker.hex() in names]
    need(len(found) <= 1, "Marker appears in multiple selected parents")
    return found[0] if found else None


def exact_transition(
    before: dict[str, list[str]],
    after: dict[str, list[str]],
    moved: tuple[bytes, str],
    types: tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]],
) -> None:
    """Only this marker may change parent; keep every other name and duplicate.

    Parameters
    ----------
    before : dict[str, list[str]]
        The parents' views before the move.
    after : dict[str, list[str]]
        The parents' views after the move.
    moved : tuple[bytes, str]
        The marker that was moved and the parent that now holds it.
    types : tuple[dict[str, dict[str, str]], dict[str, dict[str, str]]]
        The type and creator of each name, before and after.
    """
    marker, found = moved
    before_types, after_types = types
    need(set(before) == set(after) == set(PARENTS), "Incomplete parent views")
    previous = location(before, marker)
    need(previous == "S", "Marker was not uniquely in source")
    for parent in PARENTS:
        expected = collections.Counter(before[parent])
        if parent == "S":
            expected[marker.hex()] -= 1
            if expected[marker.hex()] == 0:
                del expected[marker.hex()]
        if parent == found:
            expected[marker.hex()] += 1
        need(
            collections.Counter(after[parent]) == expected,
            "Unexpected name or duplicate in owned parent",
        )
        expected_types = dict(before_types[parent])
        if parent == "S":
            marker_type = expected_types.pop(marker.hex())
        if parent == found:
            expected_types[marker.hex()] = marker_type
        need(
            after_types[parent] == expected_types,
            "Unchanged owned file type or creator differs",
        )


def record_view(views: list[Report], label: str, reply: Report) -> Report:
    """Record what one reply shows, keeping it in the list of views.

    Returns
    -------
    dict[str, typing.Any]
        The view, with names, types, accounts or the roster identity as the
        label says.
    """
    if reply["error"]:
        return {
            "label": label,
            "status": reply["error"],
            "fields": reply["fields"],
            "names": [],
        }
    if "news" in label:
        names = news_view(reply)
    elif "accounts" in label or "roster" in label:
        names = []
    else:
        names = file_view(reply)
    value = {"label": label, "status": 0, "fields": reply["fields"], "names": names}
    if label.endswith("files-root") or label.startswith(("setup-view-", "after-view-")):
        value["types"] = file_types(reply)
    if "accounts" in label:
        value["accounts"] = enumeration(reply)
    if "roster" in label:
        rows = roster(reply)
        need(len(rows) == 1, "Non-solo admin roster")
        value["uid"] = rows[0]["uid"]
        value["name_hex"] = rows[0]["name_hex"]
    views.append(value)
    return value
