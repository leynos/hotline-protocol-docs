"""Read and check single frames of the positive alias rehearsal.

Part of the missing-alias runner (``native_missing_alias_control``), whose
``CAPTURE_MODULES`` lists this module and which re-exports every public name
below. Each check fails closed with a ``ValueError`` that names what differed.
"""

import hashlib
import typing as typ

from native_rate304_control import Wire as RateWire
from native_wire_names import (
    FIELD_FILE_CREATOR,
    FIELD_FILE_NAME,
    FIELD_FILE_SIZE,
    FIELD_FILE_TYPE,
)
from verify_native_shx import fields

type Report = dict[str, typ.Any]

AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
ALIAS_205 = bytes.fromhex("553534542028616c69617329")
ALIAS_206 = b"M54X"
ALIAS_213 = b"U54T"
FIELD_ALIAS_KIND = 205
NO_TAIL = ""  # the text of a frame that leaves nothing unconsumed
SCREEN_KEYS = (
    "target",
    "make-alias-menu",
    "alias-result",
    "copy-menu",
    "paste-menu",
    "destination",
)


class Wire(RateWire):
    """The 304 collector, with the request count and the progress kept on failure."""

    request_count: int = 0
    partial: dict[str, typ.Any]


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


def digest(raw: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The SHA-256 in lower-case hexadecimal.
    """
    return hashlib.sha256(raw).hexdigest()


def exact_fields(frame: Report) -> dict[int, bytes]:
    """Read a frame's fields, refusing a malformed or repeated one.

    Returns
    -------
    dict[int, bytes]
        The field values by identifier.
    """
    value = fields(frame)
    need(
        frame["flags"] == 0
        and frame["total_size"] == frame["data_size"]
        and frame["declared_field_count"] == len(frame["fields"])
        and len(value) == len(frame["fields"])
        and frame.get("unconsumed_hex") == NO_TAIL,
        "Malformed/repeated reply field",
    )
    return value


def direct(frames: list[Report], identifier: int) -> Report:
    """Find the single successful direct reply to one request.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    matches = [
        f
        for f in frames
        if f["connection"] == "main"
        and f["type"] == 0
        and f["is_reply"] == 1
        and f["id"] == identifier
    ]
    need(len(matches) == 1, f"Missing/duplicate reply {identifier}")
    frame = matches[0]
    need(
        frame["flags"] == 0 and frame["error"] == 0,
        f"Native status/error for {identifier}",
    )
    return frame


def positive_alias(frame: Report, name: bytes) -> Report:
    """Require a 206 reply to identify the resolved tagged alias.

    Returns
    -------
    dict[str, typing.Any]
        The alias name, field 207, the field identifiers and the raw hash.
    """
    value = exact_fields(frame)
    need(
        value.get(FIELD_FILE_NAME) == name
        and value.get(FIELD_ALIAS_KIND) == ALIAS_205
        and value.get(FIELD_FILE_CREATOR) == ALIAS_206
        and value.get(FIELD_FILE_TYPE) == ALIAS_213,
        "206 did not identify the resolved tagged alias",
    )
    return {
        "name_hex": name.hex(),
        "field207_hex": value.get(FIELD_FILE_SIZE, b"").hex(),
        "fields": sorted(value),
        "raw_sha256": digest(bytes.fromhex(frame["raw_hex"])),
    }
