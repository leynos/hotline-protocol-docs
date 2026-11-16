"""Frame lookups of the failed 303 load attempt, shared by its checks and verifier.

The names are re-exported by verify_native_diagnostic_load, which the tests import.
"""

from native_wire_names import FIELD_USER_ID, FRAME_HEADER_BYTES
from protocol_capture import decode_frame
from verify_native_auth import roster
from verify_native_core import require
from verify_native_shx import fields

CASES = ("preflight", "seed", "cleanup")
FIXTURE_NAME = b"framing-fixture"  # the account name that the rosters must list
DIAGNOSTIC_TYPE = 303  # the request whose replies these checks read
UID_BYTES = 2  # a session UID is a big-endian 16-bit value
SEND_HEX_CHARS = 2 * FRAME_HEADER_BYTES  # hex digits of one frame header, two per byte


def reply(report: dict, identifier: int) -> dict:
    """Return the one reply with ``identifier`` on connection ``a``.

    Parameters
    ----------
    report : dict
        A verified capture report.
    identifier : int
        The transaction identifier of the reply.

    Returns
    -------
    dict
        The reply frame.
    """
    matches = [
        f
        for f in report["frames"]
        if f["connection"] == "a" and f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(len(matches) == 1, f"Reply {identifier} missing or duplicate")
    return matches[0]


def sent(report: dict, kind: int, identifier: int) -> dict:
    """Return the one request of ``kind`` and ``identifier`` sent on connection ``a``.

    Parameters
    ----------
    report : dict
        A verified capture report.
    kind : int
        The transaction type of the request.
    identifier : int
        The transaction identifier of the request.

    Returns
    -------
    dict
        The decoded request frame.
    """
    matches = [
        decode_frame(bytes.fromhex(e["hex"]))
        for e in report["events"]
        if e["event"] == "send"
        and e["connection"] == "a"
        and len(e["hex"]) >= SEND_HEX_CHARS
        and e["hex"][:8] != "54525450"
    ]
    selected = [f for f in matches if f["type"] == kind and f["id"] == identifier]
    require(len(selected) == 1, f"Request {kind}/{identifier} missing or duplicate")
    return selected[0]


def current_uid(report: dict, roster_id: int, diagnostic_id: int) -> str:
    """Check the current administrator roster and return the same-session UID.

    Parameters
    ----------
    report : dict
        A verified capture report.
    roster_id : int
        The identifier of the roster reply.
    diagnostic_id : int
        The identifier of the 303 request that must target the same session.

    Returns
    -------
    str
        The UID as hexadecimal text.
    """
    rows = roster(reply(report, roster_id))
    require(
        len(rows) == 1 and rows[0]["name_hex"] == FIXTURE_NAME.hex(),
        "Current admin roster ambiguous",
    )
    uid = rows[0]["uid"].to_bytes(UID_BYTES, "big")
    require(
        fields(sent(report, DIAGNOSTIC_TYPE, diagnostic_id)) == {FIELD_USER_ID: uid},
        "303 did not target same-session UID",
    )
    return uid.hex()
