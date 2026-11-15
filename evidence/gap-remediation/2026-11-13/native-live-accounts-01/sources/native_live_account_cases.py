"""Prepare live account propagation/deletion and server restart observations."""

from native_auth_cases import authentication, complement
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login, packet, payload, quiet, read, send

LIVE = b"m-live27"
DELETED = b"m-delete27"
OLD = b"live-old27"
CHANGED = b"live-changed27"
FINAL = b"live-final27"
DELETE_PASSWORD = b"delete-pass27"
ACCESS = bytes.fromhex("2000000000000000")
ALPHA = b"Stored Alpha27"
BETA = b"Stored Beta27"
DELETE_NAME = b"Delete Target27"


def account_values(
    key: bytes,
    password: bytes,
    name: bytes,
    access: bytes,
    attribute: bytes = b"live27",
) -> list[tuple[int, bytes]]:
    return [
        (105, complement(key)),
        (106, complement(password)),
        (102, name),
        (110, access),
        (111, attribute),
    ]


def subject(name: str, key: bytes, password: bytes, icon: int) -> list[dict]:
    steps = [{**s, "connection": name} for s in login()[:3]]
    return steps + [
        authentication(
            key,
            password,
            name=b"requested-" + name.encode(),
            icon=icon.to_bytes(2, "big"),
            connection=name,
        ),
        read(name),
        read(name),
        read(name),
    ]


def request(
    connection: str,
    kind: int,
    identifier: int,
    values: list[tuple[int, bytes]] | None = None,
) -> list[dict]:
    return [
        send(packet(kind, identifier, payload(values or [])), connection),
        read(connection, match_frame={"is_reply": 1, "id": identifier}),
    ]


def settled() -> list[dict]:
    return [
        {"op": "expect_quiet", "connection": name, "timeout": 3}
        for name in ["one", "two", "main"]
    ]


def preflight() -> tuple[list[dict], dict]:
    steps = login() + exchange(348, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    for identifier, key in [(20, LIVE), (21, DELETED)]:
        steps += exchange(352, identifier, [(105, key)])
    return steps + [close()], {"kind": "live-account-preflight"}


def seed() -> tuple[list[dict], dict]:
    steps = login()
    for identifier, key, password, name in [
        (10, LIVE, OLD, ALPHA),
        (11, DELETED, DELETE_PASSWORD, DELETE_NAME),
    ]:
        steps += exchange(350, identifier, account_values(key, password, name, ACCESS))
        steps += exchange(352, identifier + 10, [(105, key)])
    return steps + [close()], {"kind": "live-account-seed"}


def edit() -> tuple[list[dict], dict]:
    steps = login() + subject("one", LIVE, OLD, 7) + subject("two", LIVE, OLD, 8)
    steps += exchange(300, 10, []) + request("one", 500, 80) + request("two", 500, 80)
    steps += exchange(353, 11, account_values(LIVE, CHANGED, BETA, bytes(8)))
    steps += exchange(300, 12, []) + request("one", 500, 90) + request("two", 500, 90)
    for name in ["one", "two"]:
        steps += request(name, 202, 91, [(201, b"m-live27-denied")])
    steps += settled()
    steps += exchange(353, 21, account_values(LIVE, FINAL, BETA, bytes(8)))
    steps += (
        exchange(300, 22, [])
        + request("one", 500, 92)
        + request("two", 500, 92)
        + settled()
    )
    attribute = account_values(LIVE, FINAL, BETA, bytes(8), b"attribute-only27")
    attribute = [(k, b"\0" if k == 106 else v) for k, v in attribute]
    steps += exchange(353, 31, attribute)
    steps += (
        exchange(300, 32, [])
        + request("one", 500, 93)
        + request("two", 500, 93)
        + settled()
    )
    steps += [close("one"), close("two"), {"op": "pause", "seconds": 3}]
    steps += (
        exchange(300, 40, []) + [{"op": "pause", "seconds": 3}] + exchange(300, 41, [])
    )
    return steps + [close()], {"kind": "live-account-edit"}


def delete() -> tuple[list[dict], dict]:
    steps = (
        login()
        + subject("one", DELETED, DELETE_PASSWORD, 7)
        + subject("two", DELETED, DELETE_PASSWORD, 8)
    )
    steps += exchange(300, 10, []) + request("one", 500, 80) + request("two", 500, 80)
    steps += exchange(351, 11, [(105, complement(DELETED))])
    steps += [
        read("one", match_frame={"type": 104}),
        read("two", match_frame={"type": 104}),
        {"op": "pause", "seconds": 3},
    ]
    steps += (
        exchange(300, 12, []) + [{"op": "pause", "seconds": 3}] + exchange(300, 13, [])
    )
    steps += exchange(352, 14, [(105, DELETED)])
    return steps + [close("one"), close("two"), close()], {
        "kind": "live-account-delete"
    }


def probe(label: str) -> tuple[list[dict], dict]:
    values = {
        "old": (LIVE, OLD, False),
        "intermediate": (LIVE, CHANGED, False),
        "final": (LIVE, FINAL, True),
        "deleted": (DELETED, DELETE_PASSWORD, False),
    }
    key, password, success = values[label]
    steps = login()[:3] + [authentication(key, password), read()]
    if success:
        steps += [read(), read()] + exchange(500, 90, [])
    return steps + [quiet(), close()], {
        "kind": "live-account-reconnect",
        "case": label,
        "success": success,
    }


def finalize() -> tuple[list[dict], dict]:
    steps = login() + upload(80, b"m-live27-flush", b"\0\0")
    steps += exchange(352, 10, [(105, LIVE)]) + exchange(352, 11, [(105, DELETED)])
    steps += exchange(348, 20, [])
    return steps + [close()], {"kind": "live-account-final"}


def inspect() -> tuple[list[dict], dict]:
    steps = (
        login() + exchange(352, 10, [(105, LIVE)]) + exchange(352, 11, [(105, DELETED)])
    )
    steps += exchange(348, 20, []) + exchange(200, 21, [(202, b"\0\0")])
    return steps + [close()], {"kind": "live-account-inspect"}


def stopped() -> tuple[list[dict], dict]:
    steps = [{**s, "timeout": 3} for s in login()[:3]] + [close()]
    return steps, {
        "kind": "live-account-stopped-listener",
        "expected": "No successful native handshake while application is stopped",
    }


def cleanup() -> tuple[list[dict], dict]:
    steps = login() + exchange(351, 10, [(105, complement(LIVE))])
    steps += exchange(204, 11, [(201, b"m-live27-flush")])
    steps += exchange(348, 20, []) + exchange(200, 21, [(202, b"\0\0")])
    return steps + [close()], {"kind": "live-account-cleanup"}


def publish_cleanup() -> tuple[list[dict], dict]:
    steps = login() + upload(80, b"m-live27-publish", b"\0\0")
    steps += exchange(348, 20, []) + exchange(200, 21, [(202, b"\0\0")])
    return steps + [close()], {"kind": "live-account-publish"}


def remove_publisher() -> tuple[list[dict], dict]:
    steps = login() + exchange(204, 10, [(201, b"m-live27-publish")])
    steps += exchange(348, 20, []) + exchange(200, 21, [(202, b"\0\0")])
    return steps + [close()], {"kind": "live-account-remove"}
