"""Prepare owned rename/comment presence, privilege and partial-effect cases."""

from native_alias_cases import body
from native_auth_cases import authentication, complement
from native_folder_cases import path
from native_mkdir_cases import exchange
from native_plan import close, connect, eof, login, packet, payload, read, send

ROOT = b"mothra-meta21"
BASE = path((ROOT,))
PASSWORD = b"meta-pass"
ACCOUNTS = {
    "comment": (
        b"m-meta21-comment",
        ((1 << (63 - 28)) | (1 << (63 - 29))).to_bytes(8, "big"),
    ),
    "rename": (
        b"m-meta21-rename",
        ((1 << (63 - 3)) | (1 << (63 - 7))).to_bytes(8, "big"),
    ),
    "neither": (b"m-meta21-neither", bytes(8)),
}


def specs() -> list[dict]:
    patterns = [
        ("both-omitted", None, None, "admin"),
        ("empty-name", b"", None, "admin"),
        ("same-name", b"SAME", None, "admin"),
        ("name-only", b"NEW", None, "admin"),
        ("empty-comment", None, b"", "admin"),
        ("nul-comment", None, b"\0", "admin"),
        ("new-comment", None, b"new-comment", "admin"),
        ("both-new", b"NEW", b"new-comment", "admin"),
        ("comment-before-conflict", b"occupied", b"partial-comment", "admin"),
        ("comment-only-privilege-combined", b"NEW", b"partial-comment", "comment"),
        ("rename-only-privilege-combined", b"NEW", b"blocked-comment", "rename"),
        ("rename-only-privilege-name", b"NEW", None, "rename"),
        ("comment-only-privilege-name", b"NEW", None, "comment"),
        ("neither-noop", None, None, "neither"),
        ("neither-empty-comment", None, b"", "neither"),
        ("comment255", None, b"x" * 255, "admin"),
        ("comment256", None, b"x" * 256, "admin"),
        ("comment-interior-nul", None, b"aa\0bb", "admin"),
    ]
    result = []
    for folder in [False, True]:
        for index, (label, new, comment, role) in enumerate(patterns):
            name = (b"d" if folder else b"f") + str(index).encode().rjust(2, b"0")
            new = name if new == b"SAME" else b"n-" + name if new == b"NEW" else new
            result.append(
                {
                    "case": ("dir-" if folder else "file-") + label,
                    "folder": folder,
                    "name_hex": name.hex(),
                    "new_hex": None if new is None else new.hex(),
                    "comment_hex": None if comment is None else comment.hex(),
                    "role": role,
                }
            )
    return result


def preflight() -> dict:
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    for identifier, (name, _) in enumerate(ACCOUNTS.values(), 20):
        steps += exchange(352, identifier, [(105, name)])
    return {"preflight": (steps + [close()], {"kind": "metadata-preflight"})}


def upload(identifier: int, name: bytes) -> list[dict]:
    value = body(b"metadata-data", b"", b"TEXT", b"MOTH", b"base-comment")
    channel, reference = f"up{identifier}", f"ref{identifier}"
    return [
        send(
            packet(
                203,
                identifier,
                payload(
                    [(201, name), (202, BASE), (108, len(value).to_bytes(4, "big"))]
                ),
            )
        ),
        read(
            match_frame={"is_reply": 1, "id": identifier},
            save_field={"name": reference, "id": 107},
        ),
        connect(channel, "data"),
        send(
            "48545846{"
            + reference
            + "}"
            + len(value).to_bytes(4, "big").hex()
            + "00000000"
            + value.hex(),
            channel,
        ),
        eof(channel),
        close(channel),
    ]


def seed() -> dict:
    steps = login()
    for identifier, (name, privileges) in enumerate(ACCOUNTS.values(), 20):
        steps += exchange(
            350,
            identifier,
            [
                (105, complement(name)),
                (106, complement(PASSWORD)),
                (102, name),
                (110, privileges),
            ],
        )
        steps += exchange(352, identifier + 10, [(105, name)])
    steps += exchange(205, 50, [(201, ROOT)])
    steps += upload(60, b"occupied")
    for identifier, spec in enumerate(specs(), 100):
        name = bytes.fromhex(spec["name_hex"])
        if spec["folder"]:
            steps += exchange(205, identifier, [(201, name), (202, BASE)])
            steps += exchange(
                207,
                identifier + 100,
                [(201, name), (202, BASE), (210, b"base-comment")],
            )
        else:
            steps += upload(identifier, name)
    steps += exchange(200, 500, [(202, BASE)]) + [close()]
    return {"seed": (steps, {"kind": "metadata-seed"})}


def mutations() -> dict:
    result = {}
    for spec in specs():
        steps = login()
        if spec["role"] != "admin":
            steps[3] = authentication(ACCOUNTS[spec["role"]][0], PASSWORD)
        name = bytes.fromhex(spec["name_hex"])
        values = [(201, name), (202, BASE)]
        steps += exchange(206, 10, values) + exchange(200, 11, [(202, BASE)])
        updates = list(values)
        for field, key in [(210, "comment_hex"), (211, "new_hex")]:
            if spec[key] is not None:
                updates.append((field, bytes.fromhex(spec[key])))
        steps += exchange(207, 12, updates)
        # Both names are observed, so an error cannot hide a partial rename.
        steps += exchange(206, 20, values)
        new = (
            name
            if spec["new_hex"] is None or spec["new_hex"] == ""
            else bytes.fromhex(spec["new_hex"])
        )
        steps += exchange(206, 21, [(201, new), (202, BASE)])
        steps += exchange(200, 22, [(202, BASE)]) + exchange(500, 90, [])
        steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
        result[spec["case"]] = (steps, {"kind": "metadata-mutation", **spec})
    return result


def cleanup() -> dict:
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    steps += exchange(204, 20, [(201, ROOT)])
    for identifier, (name, _) in enumerate(ACCOUNTS.values(), 30):
        steps += exchange(351, identifier, [(105, name)])
        steps += exchange(352, identifier + 10, [(105, name)])
    steps += exchange(200, 90, [(202, b"\0\0")]) + [close()]
    return {"cleanup": (steps, {"kind": "metadata-cleanup"})}
