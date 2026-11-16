"""Name the owned batch accounts and encode the account records of the batches.

``key`` gives an owned account its complemented login, ``record`` and
``deletion`` encode batch rows, and ``padded`` extends a record to a given
length. The planners in ``native_account_batch_specs`` and
``native_account_batch_cases`` share these names.
"""

import typing as typ

from native_auth_cases import complement
from native_plan import Action, payload
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_ACCOUNT_ATTRIBUTE,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
)

type Spec = dict[str, typ.Any]
type Plan = tuple[list[Action], dict[str, typ.Any]]

PASSWORD = b"batch-pass28"
ROLES = {
    "create": bytes.fromhex("0002000000000000"),
    "delete": bytes.fromhex("0001000000000000"),
    "update": bytes.fromhex("0000400000000000"),
    "none": bytes(ACCESS_BITMAP_BYTES),
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
OWNED = ["actor-" + name for name in ROLES] + TARGETS + NEW
EXTRA = ["clash2-old", "clash2-new", "clash2-first", "clash2-last"]
SOURCE_PASSWORD = b"source-pass28"
TARGET_PASSWORD = b"target-pass28"

# carries the complemented login of the account that a row names
NAMED_ACCOUNT_FIELD = 101
# a field ID that native_wire_names does not name
UNNAMED_FIELD_ID = 65000
WORD_BYTES = 2  # a big-endian 16-bit word
TLV_HEADER_BYTES = 4  # the ID word and the length word of one field
EXTRA_FIELD_COUNT = 1  # the count word grows by one for the filler field
FILL_BYTE = b"P"
UNKNOWN_ACCOUNT_MESSAGE = "Unknown owned batch account"


def key(label: str) -> bytes:
    """Return the complemented-login key of an owned batch account.

    Returns
    -------
    bytes
        The ``m-b28-`` login of ``label``.

    Raises
    ------
    ValueError
        If ``label`` is not an owned or supplementary batch account.
    """
    if label not in OWNED + EXTRA:
        raise ValueError(UNKNOWN_ACCOUNT_MESSAGE)
    return ("m-b28-" + label).encode()


def record(  # ruff: ignore[too-many-arguments]  # pylint: disable=too-many-arguments  # the callers' shape: five arguments, as the planners pass them
    label: str,
    *,
    old: str | None = None,
    name: bytes | None = None,
    password: bytes | None = None,
    access: bytes = bytes(ACCESS_BITMAP_BYTES),
) -> bytes:
    """Encode the account record that creates or replaces an owned account.

    Returns
    -------
    bytes
        The payload of the record; an ``old`` login adds the field that names
        the account being replaced.
    """
    values = [
        (FIELD_LOGIN, complement(key(label))),
        (FIELD_NAME, b"Batch28-" + label.encode() if name is None else name),
        (FIELD_PASSWORD, complement(PASSWORD) if password is None else password),
        (FIELD_ACCESS_BITMAP, access),
        (FIELD_ACCOUNT_ATTRIBUTE, b"b28"),
    ]
    if old is not None:
        values.insert(0, (NAMED_ACCOUNT_FIELD, complement(key(old))))
    return payload(values)


def deletion(label: str) -> bytes:
    """Encode the row that deletes an owned batch account.

    Returns
    -------
    bytes
        The payload with the complemented login of ``label`` only.
    """
    return payload([(NAMED_ACCOUNT_FIELD, complement(key(label)))])


def padded(label: str, length: int) -> bytes:
    """Encode the record of ``label`` extended by a filler field to ``length``.

    Returns
    -------
    bytes
        The record with one more field, whose filler makes the total ``length``
        bytes, followed by the filler.
    """
    raw = record(label)
    filler = length - len(raw) - TLV_HEADER_BYTES
    return (
        (int.from_bytes(raw[:WORD_BYTES], "big") + EXTRA_FIELD_COUNT).to_bytes(
            WORD_BYTES, "big"
        )
        + raw[WORD_BYTES:]
        + UNNAMED_FIELD_ID.to_bytes(WORD_BYTES, "big")
        + filler.to_bytes(WORD_BYTES, "big")
        + FILL_BYTE * filler
    )
