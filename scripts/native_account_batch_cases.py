"""Prepare owned sequential account batches and per-item permission controls."""

from native_auth_cases import authentication, complement
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login, payload, quiet, read

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
OWNED = ["actor-" + name for name in ROLES] + TARGETS + NEW
EXTRA = ["clash2-old", "clash2-new", "clash2-first", "clash2-last"]
SOURCE_PASSWORD = b"source-pass28"
TARGET_PASSWORD = b"target-pass28"


def key(label: str) -> bytes:
    if label not in OWNED + EXTRA:
        raise ValueError("Unknown owned batch account")
    return ("m-b28-" + label).encode()


def record(
    label: str,
    *,
    old: str | None = None,
    name: bytes | None = None,
    password: bytes | None = None,
    access: bytes = bytes(8),
) -> bytes:
    values = [
        (105, complement(key(label))),
        (102, b"Batch28-" + label.encode() if name is None else name),
        (106, complement(PASSWORD) if password is None else password),
        (110, access),
        (111, b"b28"),
    ]
    if old is not None:
        values.insert(0, (101, complement(key(old))))
    return payload(values)


def deletion(label: str) -> bytes:
    return payload([(101, complement(key(label)))])


def padded(label: str, length: int) -> bytes:
    raw = record(label)
    return (
        (int.from_bytes(raw[:2], "big") + 1).to_bytes(2, "big")
        + raw[2:]
        + (65000).to_bytes(2, "big")
        + (length - len(raw) - 4).to_bytes(2, "big")
        + b"P" * (length - len(raw) - 4)
    )


def specifications() -> list[dict]:
    return [
        {
            "case": "ordered-outer-ids",
            "role": "admin",
            "rows": [
                (0, record("order-a")),
                (65000, record("order-b", old="order-a", password=b"\0")),
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
                    101,
                    record(
                        "collision", name=b"Attempted overwrite", password=b"attempt"
                    ),
                ),
                (101, record("after-collision")),
            ],
            "names": ["collision", "after-collision"],
        },
        {
            "case": "empty-copy-continues",
            "role": "admin",
            "rows": [(101, b""), (101, record("after-empty-copy"))],
            "names": ["after-empty-copy"],
        },
        {
            "case": "empty-tlv-continues",
            "role": "admin",
            "rows": [(101, payload([])), (101, record("after-empty-tlv"))],
            "names": ["after-empty-tlv"],
        },
        {"case": "empty-batch", "role": "admin", "rows": [], "names": ["collision"]},
        {
            "case": "create-update-denied",
            "role": "create",
            "rows": [
                (101, record("created-before-deny")),
                (101, record("create-u", old="create-u", password=b"\0")),
                (101, record("skipped-create")),
            ],
            "names": ["created-before-deny", "create-u", "skipped-create"],
        },
        {
            "case": "delete-create-denied",
            "role": "delete",
            "rows": [
                (101, deletion("delete-a")),
                (101, record("denied-create")),
                (101, deletion("delete-b")),
            ],
            "names": ["delete-a", "denied-create", "delete-b"],
        },
        {
            "case": "update-delete-denied",
            "role": "update",
            "rows": [
                (101, record("update-a", old="update-a", password=b"\0")),
                (101, deletion("update-b")),
                (101, record("update-b", old="update-b", password=b"\0")),
            ],
            "names": ["update-a", "update-b"],
        },
        {
            "case": "subset-denied",
            "role": "create",
            "rows": [
                (101, record("grant-denied", access=bytes.fromhex("2000000000000000"))),
                (101, record("grant-skipped")),
            ],
            "names": ["grant-denied", "grant-skipped"],
        },
        {
            "case": "subset-exempt27",
            "role": "create",
            "rows": [
                (101, record("grant-exempt", access=bytes.fromhex("0000001000000000")))
            ],
            "names": ["grant-exempt"],
        },
        {
            "case": "zero-role-denied",
            "role": "none",
            "rows": [(101, record("none-denied"))],
            "names": ["none-denied"],
        },
        {
            "case": "rename-success",
            "role": "admin",
            "rows": [
                (
                    101,
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
                    101,
                    payload(
                        [
                            (101, complement(key("defaults"))),
                            (105, complement(key("defaults"))),
                            (106, b"\0"),
                        ]
                    ),
                )
            ],
            "names": ["defaults"],
        },
        {
            "case": "new-nul-password",
            "role": "admin",
            "rows": [(101, record("nul-new", password=b"\0"))],
            "names": ["nul-new"],
        },
        {
            "case": "nested512",
            "role": "admin",
            "rows": [(101, padded("pad512", 512))],
            "names": ["pad512"],
        },
        {
            "case": "nested513",
            "role": "admin",
            "rows": [(101, padded("pad513", 513))],
            "names": ["pad513"],
        },
        {
            "case": "identity-after-limit",
            "role": "admin",
            "rows": [
                (
                    101,
                    (6).to_bytes(2, "big")
                    + payload([(65000, b"P" * 507)])[2:]
                    + record("late")[2:],
                ),
                (101, record("after-late")),
            ],
            "names": ["late", "after-late"],
        },
        {
            "case": "rename-collision",
            "role": "admin",
            "rows": [
                (101, record("clash-first")),
                (101, record("clash-new", old="clash-old", password=b"\0")),
                (101, record("clash-skipped")),
            ],
            "names": ["clash-first", "clash-old", "clash-new", "clash-skipped"],
        },
    ]


def preflight() -> tuple[list[dict], dict]:
    steps = login() + exchange(348, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    for identifier, label in enumerate(OWNED, 100):
        steps += exchange(352, identifier, [(105, key(label))])
    return steps + [close()], {"kind": "account-batch-preflight"}


def seed() -> tuple[list[dict], dict]:
    steps = login()
    for identifier, label in enumerate(OWNED[:14], 100):
        access = (
            ROLES[label.removeprefix("actor-")]
            if label.startswith("actor-")
            else bytes(8)
        )
        values = [
            (105, complement(key(label))),
            (106, complement(PASSWORD)),
            (102, b"Seed28-" + label.encode()),
            (110, access),
            (111, b"seed28"),
        ]
        steps += exchange(350, identifier, values) + exchange(
            352, identifier + 100, [(105, key(label))]
        )
    steps += upload(80, b"m-b28-seed-flush", b"\0\0")
    return steps + [{"op": "pause", "seconds": 3}, close()], {
        "kind": "account-batch-seed"
    }


def batch(spec: dict) -> tuple[list[dict], dict]:
    steps = login()
    if spec["role"] != "admin":
        steps[3] = authentication(key("actor-" + spec["role"]), PASSWORD)
    steps += exchange(349, 10, spec["rows"]) + exchange(500, 90, [])
    return steps + [quiet(), close()], {
        "kind": "account-batch-mutation",
        "case": spec["case"],
        "role": spec["role"],
    }


def inspect(spec: dict) -> tuple[list[dict], dict]:
    steps = login()
    for identifier, label in enumerate(spec["names"], 100):
        steps += exchange(352, identifier, [(105, key(label))])
    steps += exchange(348, 90, [])
    return steps + [close()], {
        "kind": "account-batch-inspect",
        "case": spec["case"],
        "names": spec["names"],
    }


def probe_nul() -> tuple[list[dict], dict]:
    steps = (
        login()[:3]
        + [authentication(key("nul-new"), b"\xff"), read(), read(), read()]
        + exchange(500, 90, [])
    )
    return steps + [quiet(), close()], {"kind": "account-batch-nul-login"}


def finalization() -> tuple[list[dict], dict]:
    steps = login() + upload(80, b"m-b28-final-flush", b"\0\0")
    for identifier, label in enumerate(OWNED, 100):
        steps += exchange(352, identifier, [(105, key(label))])
    return steps + exchange(348, 90, []) + [close()], {"kind": "account-batch-final"}


def cleanup(existing: list[str]) -> tuple[list[dict], dict]:
    if len(set(existing)) != len(existing) or not set(existing) <= set(OWNED + EXTRA):
        raise ValueError("Cleanup requires a unique observed owned inventory")
    steps = login()
    for identifier, label in enumerate(existing, 100):
        steps += exchange(351, identifier, [(105, complement(key(label)))])
    for identifier, name in [
        (20, b"m-b28-seed-flush"),
        (21, b"m-b28-final-flush"),
        (22, b"m-b28-supp-seed-flush"),
        (23, b"m-b28-supp-final-flush"),
    ]:
        steps += exchange(204, identifier, [(201, name)])
    steps += exchange(348, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "account-batch-cleanup", "existing": existing}


def supplementary_seed() -> tuple[list[dict], dict]:
    steps = login()
    for identifier, label in enumerate(EXTRA, 100):
        steps += exchange(352, identifier, [(105, key(label))])
    for identifier, label, password in [
        (10, "clash2-old", SOURCE_PASSWORD),
        (11, "clash2-new", TARGET_PASSWORD),
    ]:
        steps += exchange(
            350,
            identifier,
            [
                (105, complement(key(label))),
                (106, complement(password)),
                (102, b"Distinct28-" + label.encode()),
                (110, bytes(8)),
                (111, b"distinct28"),
            ],
        )
    steps += upload(80, b"m-b28-supp-seed-flush", b"\0\0")
    return steps + [close()], {"kind": "account-batch-distinct-seed"}


def supplementary_spec() -> dict:
    return {
        "case": "distinct-rename-collision",
        "role": "admin",
        "rows": [
            (101, record("clash2-first")),
            (
                101,
                record(
                    "clash2-new",
                    old="clash2-old",
                    name=b"Distinct overwritten28",
                    password=b"\0",
                ),
            ),
            (101, record("clash2-last")),
        ],
        "names": EXTRA,
    }


def supplementary_probe(label: str) -> tuple[list[dict], dict]:
    key_label, password, success = {
        "source": ("clash2-old", SOURCE_PASSWORD, True),
        "destination-source": ("clash2-new", SOURCE_PASSWORD, True),
        "destination-old": ("clash2-new", TARGET_PASSWORD, False),
    }[label]
    steps = login()[:3] + [authentication(key(key_label), password), read()]
    if success:
        steps += [read(), read()] + exchange(500, 90, [])
    return steps + [quiet(), close()], {
        "kind": "account-batch-distinct-login",
        "case": label,
        "success": success,
    }


def supplementary_final() -> tuple[list[dict], dict]:
    steps = login() + upload(80, b"m-b28-supp-final-flush", b"\0\0")
    for identifier, label in enumerate(OWNED + EXTRA, 100):
        steps += exchange(352, identifier, [(105, key(label))])
    return steps + exchange(348, 90, []) + [close()], {
        "kind": "account-batch-distinct-final"
    }


def publish_cleanup() -> tuple[list[dict], dict]:
    steps = login() + upload(80, b"m-b28-publish", b"\0\0")
    steps += exchange(348, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "account-batch-publish"}


def remove_publisher() -> tuple[list[dict], dict]:
    steps = login() + exchange(204, 10, [(201, b"m-b28-publish")])
    steps += exchange(348, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "account-batch-remove"}
