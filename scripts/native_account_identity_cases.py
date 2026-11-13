"""Prepare owned account identity, kick-protection and self-delete contrasts."""

from native_auth_cases import authentication, complement
from native_live_account_cases import account_values, request, subject
from native_mkdir_cases import exchange
from native_plan import close, login, packet, payload, quiet, read, send

PASSWORD = b"identity-pass29"
CHANGED = b"identity-changed29"
KEYS = {
    "protected": b"m-id29-protected",
    "self": b"m-id29-self",
    "duplicate": b"m-id29-duplicate",
}
ACCESS = {
    "protected": bytes.fromhex("0000010000000000"),
    "self": bytes.fromhex("0001010000000000"),
    "duplicate": bytes(8),
}


def values(label: str, *, changed: bool = False) -> list[tuple[int, bytes]]:
    return account_values(
        KEYS[label],
        CHANGED if changed else PASSWORD,
        (b"Changed29-" if changed else b"Identity29-") + label.encode(),
        ACCESS[label],
        b"identity29",
    )


def inspect() -> tuple[list[dict], dict]:
    steps = login() + exchange(348, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    for identifier, key in enumerate(KEYS.values(), 20):
        steps += exchange(352, identifier, [(105, key)])
    return steps + [close()], {"kind": "account-identity-inspect"}


def seed() -> tuple[list[dict], dict]:
    steps = login()
    for identifier, label in enumerate(KEYS, 10):
        steps += exchange(350, identifier, values(label))
        steps += exchange(352, identifier + 10, [(105, KEYS[label])])
    return steps + [close()], {"kind": "account-identity-seed"}


def duplicate(uppercase: bool = False) -> tuple[list[dict], dict]:
    fields = values("duplicate", changed=True)
    if uppercase:
        fields = [
            (k, complement(KEYS["duplicate"].upper()) if k == 105 else v)
            for k, v in fields
        ]
    steps = login() + exchange(350, 10, fields)
    steps += exchange(352, 20, [(105, KEYS["duplicate"])])
    steps += exchange(352, 21, [(105, KEYS["duplicate"].upper())])
    steps += exchange(348, 30, []) + exchange(500, 90, [])
    return steps + [quiet(), close()], {
        "kind": "account-identity-duplicate",
        "uppercase": uppercase,
    }


def target_case(label: str) -> tuple[list[dict], dict]:
    if label not in {"protected", "self"}:
        raise ValueError("Owned protected or self-delete target required")
    steps = login() + subject("target", KEYS[label], PASSWORD, 29)
    steps += [
        read(
            match_frame={"type": 301},
            save_fields={"target_uid": 103},
        )
    ]
    kick = packet(110, 11, payload([(103, b"\0\0")]))
    steps += [
        send(kick[:-4] + "{target_uid}"),
        read(match_frame={"is_reply": 1, "id": 11}),
    ]
    steps += request("target", 500, 80)
    if label == "protected":
        steps += exchange(351, 12, [(105, complement(KEYS[label]))])
    else:
        steps += request("target", 351, 12, [(105, complement(KEYS[label]))])
    steps += [read("target", match_frame={"type": 104})]
    steps += [{"op": "pause", "seconds": 3}]
    steps += exchange(352, 20, [(105, KEYS[label])])
    steps += exchange(300, 30, []) + exchange(500, 90, [])
    return steps + [close("target"), close()], {
        "kind": "account-identity-target",
        "case": label,
    }


def probe(password: bytes, key: bytes) -> tuple[list[dict], dict]:
    if key not in KEYS.values():
        raise ValueError("Owned account required")
    steps = login()[:3] + [authentication(key, password), read()]
    return steps + [quiet(), close()], {
        "kind": "account-identity-login",
        "key_hex": key.hex(),
        "password_hex": password.hex(),
    }


def cleanup() -> tuple[list[dict], dict]:
    steps = login() + exchange(351, 10, [(105, complement(KEYS["duplicate"]))])
    steps += exchange(348, 20, []) + exchange(200, 21, [(202, b"\0\0")])
    return steps + [close()], {"kind": "account-identity-cleanup"}
