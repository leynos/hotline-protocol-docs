"""Prepare isolated account replacement, sentinel and password-width fixtures."""

from native_auth_cases import authentication, complement
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login, quiet, read

ACCESS = bytes.fromhex("2000000000000000")
PASSWORD = b"account-base-26"
LABELS = [
    "preserve",
    "absent",
    "empty",
    "literal-x",
    "replace32",
    "preserve32",
    "sparse",
    "attribute65",
]


def key(label: str) -> bytes:
    if label not in LABELS:
        raise ValueError("Unknown owned account case")
    return ("m-au26-" + label).encode()


def initial_password(label: str) -> bytes:
    return b"q" * 32 if label == "preserve32" else PASSWORD


def result_password(label: str) -> bytes:
    if label in {"absent", "empty"}:
        return b""
    if label == "literal-x":
        return b"\x87"
    if label == "replace32":
        return b"p" * 32
    if label == "preserve32":
        return b"q" * 31
    return PASSWORD


def values(label: str) -> list[tuple[int, bytes]]:
    return [
        (105, complement(key(label))),
        (106, complement(initial_password(label))),
        (102, b"Account26-" + label.encode()),
        (111, b"opaque26"),
        (110, ACCESS),
    ]


def preflight() -> tuple[list[dict], dict]:
    steps = login() + exchange(348, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(352, identifier, [(105, key(label))])
    return steps + [close()], {"kind": "account-update-preflight"}


def seed() -> tuple[list[dict], dict]:
    steps = login()
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(350, identifier, values(label))
        steps += exchange(352, identifier + 100, [(105, key(label))])
    steps += upload(80, b"m-au26-seed-flush", b"\0\0")
    return steps + [{"op": "pause", "seconds": 3}, close()], {
        "kind": "account-update-seed"
    }


def mutate(label: str) -> tuple[list[dict], dict]:
    fields = values(label)
    fields = [(k, v) for k, v in fields if k != 106]
    encoded = (
        None
        if label == "absent"
        else b""
        if label == "empty"
        else b"x"
        if label == "literal-x"
        else complement(b"p" * 32)
        if label == "replace32"
        else b"\0"
    )
    if label == "sparse":
        fields = [(105, complement(key(label)))]
    if label == "attribute65":
        fields = [(k, b"X" * 65 if k == 111 else v) for k, v in fields]
    if encoded is not None:
        fields.append((106, encoded))
    steps = login() + exchange(352, 10, [(105, key(label))])
    steps += exchange(353, 11, fields) + exchange(352, 12, [(105, key(label))])
    steps += exchange(500, 90, [])
    return steps + [quiet(), close()], {
        "kind": "account-update-mutation",
        "case": label,
    }


def probe(label: str, password: bytes, success: bool) -> tuple[list[dict], dict]:
    steps = login()[:3] + [authentication(key(label), password), read()]
    if success:
        steps += [read(), read()] + exchange(500, 90, [])
    return steps + [quiet(), close()], {
        "kind": "account-update-login",
        "case": label,
        "password_hex": password.hex(),
        "success": success,
    }


def finalization() -> tuple[list[dict], dict]:
    steps = login() + upload(80, b"m-au26-final-flush", b"\0\0")
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(352, identifier, [(105, key(label))])
    return steps + [close()], {"kind": "account-update-final"}


def cleanup() -> tuple[list[dict], dict]:
    steps = login()
    for identifier, label in enumerate(LABELS, 100):
        steps += exchange(351, identifier, [(105, complement(key(label)))])
    for identifier, name in [(20, b"m-au26-seed-flush"), (21, b"m-au26-final-flush")]:
        steps += exchange(204, identifier, [(201, name)])
    steps += exchange(348, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "account-update-cleanup"}
