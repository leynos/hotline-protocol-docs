"""Name the account-batch cases as rows of data, in the order they are planned.

Each case gives a label, the login role that sends the batch, the rows of the
batch request and the names that must exist after it. ``specifications`` keeps
the original order.
"""

from native_account_batch_data import (
    FILL_BYTE,
    NAMED_ACCOUNT_FIELD,
    UNNAMED_FIELD_ID,
    WORD_BYTES,
    Spec,
    deletion,
    key,
    padded,
    record,
)
from native_auth_cases import complement
from native_plan import payload
from native_wire_names import FIELD_DATA, FIELD_LOGIN, FIELD_PASSWORD

NESTED_LENGTH = 512  # the nested record length that the 512 case plans
NESTED_OVER_LENGTH = 513  # one byte past the 512 case
LIMIT_FIELD_COUNT = 6  # the field count of the identity-after-limit row
LIMIT_FILL_BYTES = 507  # the filler of the identity-after-limit row


def specifications() -> list[Spec]:
    """Name the account-batch cases in their planned order.

    Returns
    -------
    list[dict[str, typing.Any]]
        One record per case, with its ``case``, ``role``, ``rows`` and
        ``names``.
    """
    return [
        {
            "case": "ordered-outer-ids",
            "role": "admin",
            "rows": [
                (0, record("order-a")),
                (
                    UNNAMED_FIELD_ID,
                    record("order-b", old="order-a", password=b"\0"),
                ),
                (
                    0,
                    record(
                        "order-b", old="order-b", name=b"Ordered done", password=b"\0"
                    ),
                ),
            ],
            "names": ["order-a", "order-b"],
        },
        {
            "case": "collision-continues",
            "role": "admin",
            "rows": [
                (
                    FIELD_DATA,
                    record(
                        "collision", name=b"Attempted overwrite", password=b"attempt"
                    ),
                ),
                (FIELD_DATA, record("after-collision")),
            ],
            "names": ["collision", "after-collision"],
        },
        {
            "case": "empty-copy-continues",
            "role": "admin",
            "rows": [(FIELD_DATA, b""), (FIELD_DATA, record("after-empty-copy"))],
            "names": ["after-empty-copy"],
        },
        {
            "case": "empty-tlv-continues",
            "role": "admin",
            "rows": [
                (FIELD_DATA, payload([])),
                (FIELD_DATA, record("after-empty-tlv")),
            ],
            "names": ["after-empty-tlv"],
        },
        {"case": "empty-batch", "role": "admin", "rows": [], "names": ["collision"]},
        {
            "case": "create-update-denied",
            "role": "create",
            "rows": [
                (FIELD_DATA, record("created-before-deny")),
                (FIELD_DATA, record("create-u", old="create-u", password=b"\0")),
                (FIELD_DATA, record("skipped-create")),
            ],
            "names": ["created-before-deny", "create-u", "skipped-create"],
        },
        {
            "case": "delete-create-denied",
            "role": "delete",
            "rows": [
                (FIELD_DATA, deletion("delete-a")),
                (FIELD_DATA, record("denied-create")),
                (FIELD_DATA, deletion("delete-b")),
            ],
            "names": ["delete-a", "denied-create", "delete-b"],
        },
        {
            "case": "update-delete-denied",
            "role": "update",
            "rows": [
                (FIELD_DATA, record("update-a", old="update-a", password=b"\0")),
                (FIELD_DATA, deletion("update-b")),
                (FIELD_DATA, record("update-b", old="update-b", password=b"\0")),
            ],
            "names": ["update-a", "update-b"],
        },
        {
            "case": "subset-denied",
            "role": "create",
            "rows": [
                (
                    FIELD_DATA,
                    record("grant-denied", access=bytes.fromhex("2000000000000000")),
                ),
                (FIELD_DATA, record("grant-skipped")),
            ],
            "names": ["grant-denied", "grant-skipped"],
        },
        {
            "case": "subset-exempt27",
            "role": "create",
            "rows": [
                (
                    FIELD_DATA,
                    record("grant-exempt", access=bytes.fromhex("0000001000000000")),
                )
            ],
            "names": ["grant-exempt"],
        },
        {
            "case": "zero-role-denied",
            "role": "none",
            "rows": [(FIELD_DATA, record("none-denied"))],
            "names": ["none-denied"],
        },
        {
            "case": "rename-success",
            "role": "admin",
            "rows": [
                (
                    FIELD_DATA,
                    record(
                        "rename-new",
                        old="rename-old",
                        name=b"Renamed account28",
                        password=b"\0",
                    ),
                )
            ],
            "names": ["rename-old", "rename-new"],
        },
        {
            "case": "replacement-defaults",
            "role": "admin",
            "rows": [
                (
                    FIELD_DATA,
                    payload([
                        (NAMED_ACCOUNT_FIELD, complement(key("defaults"))),
                        (FIELD_LOGIN, complement(key("defaults"))),
                        (FIELD_PASSWORD, b"\0"),
                    ]),
                )
            ],
            "names": ["defaults"],
        },
        {
            "case": "new-nul-password",
            "role": "admin",
            "rows": [(FIELD_DATA, record("nul-new", password=b"\0"))],
            "names": ["nul-new"],
        },
        {
            "case": "nested512",
            "role": "admin",
            "rows": [(FIELD_DATA, padded("pad512", NESTED_LENGTH))],
            "names": ["pad512"],
        },
        {
            "case": "nested513",
            "role": "admin",
            "rows": [(FIELD_DATA, padded("pad513", NESTED_OVER_LENGTH))],
            "names": ["pad513"],
        },
        {
            "case": "identity-after-limit",
            "role": "admin",
            "rows": [
                (
                    FIELD_DATA,
                    LIMIT_FIELD_COUNT.to_bytes(WORD_BYTES, "big")
                    + payload([(UNNAMED_FIELD_ID, FILL_BYTE * LIMIT_FILL_BYTES)])[
                        WORD_BYTES:
                    ]
                    + record("late")[WORD_BYTES:],
                ),
                (FIELD_DATA, record("after-late")),
            ],
            "names": ["late", "after-late"],
        },
        {
            "case": "rename-collision",
            "role": "admin",
            "rows": [
                (FIELD_DATA, record("clash-first")),
                (
                    FIELD_DATA,
                    record("clash-new", old="clash-old", password=b"\0"),
                ),
                (FIELD_DATA, record("clash-skipped")),
            ],
            "names": ["clash-first", "clash-old", "clash-new", "clash-skipped"],
        },
    ]
