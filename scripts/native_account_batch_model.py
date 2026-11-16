"""Independent expected account states for the captured native batch matrix."""

import typing as typ

from native_auth_cases import complement
from native_plan import payload
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    ACCOUNT_ACCESS_OFFSET,
    ACCOUNT_ATTRIBUTE_LENGTH_OFFSET,
    ACCOUNT_LOGIN_LENGTH_OFFSET,
    ACCOUNT_NAME_LENGTH_OFFSET,
    ACCOUNT_PASSWORD_LENGTH_OFFSET,
    ACCOUNT_RECORD_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
)
from verify_native_core import require
from verify_native_shx import fields

type State = tuple[
    bytes, bytes, bytes, bytes
]  # name, plain password, access, attribute
type Effects = dict[str, State | None]

# The names below are imported by test_native_account_batches and by
# verify_native_account_batches (State, account_reply, apply, distinct_effects,
# distinct_seed, effects, enumeration, record, seed_states and the label lists);
# created and account_fields are kept because the original module defined them
# publicly.
__all__ = [
    "EXTRA",
    "NEW",
    "OWNED",
    "PASSWORD",
    "ROLES",
    "TARGETS",
    "State",
    "account_fields",
    "account_reply",
    "apply",
    "created",
    "distinct_effects",
    "distinct_seed",
    "effects",
    "enumeration",
    "record",
    "seed_states",
]

PASSWORD = b"batch-pass28"
ROLES = {
    "create": bytes.fromhex("0002000000000000"),
    "delete": bytes.fromhex("0001000000000000"),
    "update": bytes.fromhex("0000400000000000"),
    "none": bytes(8),
}
TARGETS = [
    "collision",
    "create-u",
    "delete-a",
    "delete-b",
    "update-a",
    "update-b",
    "rename-old",
    "clash-old",
    "clash-new",
    "defaults",
]
NEW = [
    "order-a",
    "order-b",
    "after-collision",
    "after-empty-copy",
    "after-empty-tlv",
    "created-before-deny",
    "skipped-create",
    "denied-create",
    "grant-denied",
    "grant-skipped",
    "grant-exempt",
    "none-denied",
    "rename-new",
    "nul-new",
    "pad512",
    "pad513",
    "late",
    "after-late",
    "clash-first",
    "clash-skipped",
]
OWNED = ["actor-" + role for role in ROLES] + TARGETS + NEW
EXTRA = ["clash2-old", "clash2-new", "clash2-first", "clash2-last"]
SEEDED = 14  # the actors and targets that exist before the batches run
GRANT_EXEMPT_ACCESS = bytes.fromhex("0000001000000000")
RECORD_VERSION = b"\0\1"
ACTOR_PREFIX_BYTES = len("actor-")
PRESENT_PASSWORD = b"x"  # a stand-in: the reply carries a password only as a flag
ABSENT_ERROR = 1
RECORD_FIELD_LENGTH_WORD = 2


def seed_states() -> dict[str, State]:
    """Build the states of the accounts that exist before the batches run.

    Returns
    -------
    dict[str, tuple[bytes, bytes, bytes, bytes]]
        The state of each seeded label.
    """
    return {
        label: (
            b"Seed28-" + label.encode(),
            PASSWORD,
            ROLES[label[ACTOR_PREFIX_BYTES:]]
            if label.startswith("actor-")
            else bytes(ACCESS_BITMAP_BYTES),
            b"seed28",
        )
        for label in OWNED[:SEEDED]
    }


def created(label: str) -> State:
    """Build the state of an account that a batch created with default values.

    Returns
    -------
    tuple[bytes, bytes, bytes, bytes]
        The name, password, access and attribute.
    """
    return (
        b"Batch28-" + label.encode(),
        PASSWORD,
        bytes(ACCESS_BITMAP_BYTES),
        b"b28",
    )


def effects() -> dict[str, Effects]:
    """Build the states that each batch case leaves behind, by case name.

    Returns
    -------
    dict[str, dict[str, tuple | None]]
        For each case, the accounts it changed, with ``None`` for a deletion.
    """
    none = bytes(ACCESS_BITMAP_BYTES)
    return {
        "ordered-outer-ids": {"order-b": (b"Ordered done", PASSWORD, none, b"b28")},
        "collision-continues": {"after-collision": created("after-collision")},
        "empty-copy-continues": {"after-empty-copy": created("after-empty-copy")},
        "empty-tlv-continues": {"after-empty-tlv": created("after-empty-tlv")},
        "empty-batch": {},
        "create-update-denied": {"created-before-deny": created("created-before-deny")},
        "delete-create-denied": {"delete-a": None},
        "update-delete-denied": {"update-a": created("update-a")},
        "subset-denied": {},
        "subset-exempt27": {
            "grant-exempt": (
                b"Batch28-grant-exempt",
                PASSWORD,
                GRANT_EXEMPT_ACCESS,
                b"b28",
            )
        },
        "zero-role-denied": {},
        "rename-success": {
            "rename-old": None,
            "rename-new": (b"Renamed account28", PASSWORD, none, b"b28"),
        },
        "replacement-defaults": {"defaults": (b"", PASSWORD, none, b"")},
        "new-nul-password": {"nul-new": (b"Batch28-nul-new", b"\xff", none, b"b28")},
        "nested512": {"pad512": created("pad512")},
        "nested513": {"pad513": created("pad513")},
        "identity-after-limit": {"after-late": created("after-late")},
        "rename-collision": {
            "clash-first": created("clash-first"),
            "clash-new": created("clash-new"),
            "clash-skipped": created("clash-skipped"),
        },
    }


def apply(states: dict[str, State], changes: Effects) -> None:
    """Apply a case's changes to the states, removing the deleted accounts."""
    for label, value in changes.items():
        if value is None:
            states.pop(label)
        else:
            states[label] = value


def account_fields(label: str, value: State) -> dict[int, bytes]:
    """Build the fields that a reply for an existing account must carry.

    Returns
    -------
    dict[int, bytes]
        The complemented login, the access bitmap, and the name and password
        fields when they are not empty.
    """
    name, password, access, _ = value
    result = {
        FIELD_LOGIN: complement(("m-b28-" + label).encode()),
        FIELD_ACCESS_BITMAP: access,
    }
    if name:
        result[FIELD_NAME] = name
    if password:
        result[FIELD_PASSWORD] = PRESENT_PASSWORD
    return result


def account_reply(
    frame: dict[str, typ.Any], label: str, states: dict[str, State]
) -> None:
    """Check a reply to a read of an account against the expected states."""
    if label not in states:
        require(
            frame["error"] == ABSENT_ERROR
            and fields(frame)
            == {
                FIELD_ERROR_TEXT: b"No account with login \xd2m-b28-"
                + label.encode()
                + b"\xd3."
            },
            "Expected absent batch account differs",
        )
    else:
        require(
            frame["error"] == 0
            and fields(frame) == account_fields(label, states[label]),
            "Batch account state differs",
        )


def enumeration(states: dict[str, State], baseline: list[str]) -> list[str]:
    """Build the sorted enumeration that the expected states should produce.

    Returns
    -------
    list[str]
        The baseline records and one payload per state, in hexadecimal, sorted.
    """
    return sorted(
        baseline
        + [
            payload(sorted(account_fields(label, value).items())).hex()
            for label, value in states.items()
        ]
    )


def record(label: str, value: State) -> bytes:
    """Build the stored account record that the expected state implies.

    Returns
    -------
    bytes
        The 734-byte record, each text field as a length word and its bytes.
    """
    name, password, access, attribute = value
    result = bytearray(ACCOUNT_RECORD_BYTES)
    result[: len(RECORD_VERSION)] = RECORD_VERSION
    result[ACCOUNT_ACCESS_OFFSET : ACCOUNT_ACCESS_OFFSET + ACCESS_BITMAP_BYTES] = access
    for offset, data in [
        (ACCOUNT_NAME_LENGTH_OFFSET, name),
        (ACCOUNT_ATTRIBUTE_LENGTH_OFFSET, attribute),
        (ACCOUNT_LOGIN_LENGTH_OFFSET, ("m-b28-" + label).encode()),
        (ACCOUNT_PASSWORD_LENGTH_OFFSET, complement(password)),
    ]:
        end = offset + RECORD_FIELD_LENGTH_WORD
        result[offset:end] = len(data).to_bytes(RECORD_FIELD_LENGTH_WORD, "big")
        result[end : end + len(data)] = data
    return bytes(result)


def distinct_seed(states: dict[str, State]) -> None:
    """Add the two accounts that the distinct-collision case starts from."""
    states["clash2-old"] = (
        b"Distinct28-clash2-old",
        b"source-pass28",
        bytes(ACCESS_BITMAP_BYTES),
        b"distinct28",
    )
    states["clash2-new"] = (
        b"Distinct28-clash2-new",
        b"target-pass28",
        bytes(ACCESS_BITMAP_BYTES),
        b"distinct28",
    )


def distinct_effects(states: dict[str, State]) -> None:
    """Apply the distinct-collision case's expected changes."""
    states["clash2-first"] = created("clash2-first")
    states["clash2-new"] = (
        b"Distinct overwritten28",
        b"source-pass28",
        bytes(ACCESS_BITMAP_BYTES),
        b"b28",
    )
    states["clash2-last"] = created("clash2-last")
