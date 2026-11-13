"""Independent expected account states for the captured native batch matrix."""

from native_auth_cases import complement
from native_plan import payload
from verify_native_core import require
from verify_native_shx import fields

State = tuple[
    bytes, bytes, bytes, bytes
]  # display name, plaintext password, access, attribute
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


def seed_states() -> dict[str, State]:
    return {
        label: (
            b"Seed28-" + label.encode(),
            PASSWORD,
            ROLES[label[6:]] if label.startswith("actor-") else bytes(8),
            b"seed28",
        )
        for label in OWNED[:14]
    }


def created(label: str) -> State:
    return b"Batch28-" + label.encode(), PASSWORD, bytes(8), b"b28"


def effects() -> dict[str, dict[str, State | None]]:
    return {
        "ordered-outer-ids": {"order-b": (b"Ordered done", PASSWORD, bytes(8), b"b28")},
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
                bytes.fromhex("0000001000000000"),
                b"b28",
            )
        },
        "zero-role-denied": {},
        "rename-success": {
            "rename-old": None,
            "rename-new": (b"Renamed account28", PASSWORD, bytes(8), b"b28"),
        },
        "replacement-defaults": {"defaults": (b"", PASSWORD, bytes(8), b"")},
        "new-nul-password": {
            "nul-new": (b"Batch28-nul-new", b"\xff", bytes(8), b"b28")
        },
        "nested512": {"pad512": created("pad512")},
        "nested513": {"pad513": created("pad513")},
        "identity-after-limit": {"after-late": created("after-late")},
        "rename-collision": {
            "clash-first": created("clash-first"),
            "clash-new": created("clash-new"),
            "clash-skipped": created("clash-skipped"),
        },
    }


def apply(states: dict[str, State], changes: dict[str, State | None]) -> None:
    for label, value in changes.items():
        if value is None:
            states.pop(label)
        else:
            states[label] = value


def account_fields(label: str, value: State) -> dict[int, bytes]:
    name, password, access, _ = value
    result = {105: complement(("m-b28-" + label).encode()), 110: access}
    if name:
        result[102] = name
    if password:
        result[106] = b"x"
    return result


def account_reply(frame: dict, label: str, states: dict[str, State]) -> None:
    if label not in states:
        require(
            frame["error"] == 1
            and fields(frame)
            == {100: b"No account with login \xd2m-b28-" + label.encode() + b"\xd3."},
            "Expected absent batch account differs",
        )
    else:
        require(
            frame["error"] == 0
            and fields(frame) == account_fields(label, states[label]),
            "Batch account state differs",
        )


def enumeration(states: dict[str, State], baseline: list[str]) -> list[str]:
    return sorted(
        baseline
        + [
            payload(sorted(account_fields(label, value).items())).hex()
            for label, value in states.items()
        ]
    )


def record(label: str, value: State) -> bytes:
    name, password, access, attribute = value
    result = bytearray(734)
    result[:2] = b"\0\1"
    result[4:12] = access
    for offset, data in [
        (528, name),
        (596, attribute),
        (664, ("m-b28-" + label).encode()),
        (700, complement(password)),
    ]:
        result[offset : offset + 2] = len(data).to_bytes(2, "big")
        result[offset + 2 : offset + 2 + len(data)] = data
    return bytes(result)


def distinct_seed(states: dict[str, State]) -> None:
    states["clash2-old"] = (
        b"Distinct28-clash2-old",
        b"source-pass28",
        bytes(8),
        b"distinct28",
    )
    states["clash2-new"] = (
        b"Distinct28-clash2-new",
        b"target-pass28",
        bytes(8),
        b"distinct28",
    )


def distinct_effects(states: dict[str, State]) -> None:
    states["clash2-first"] = created("clash2-first")
    states["clash2-new"] = b"Distinct overwritten28", b"source-pass28", bytes(8), b"b28"
    states["clash2-last"] = created("clash2-last")
