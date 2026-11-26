"""Prepare owned native aliases, metadata variants and resolved transfers."""

from native_auth_cases import authentication
from native_filp import decode
from native_folder_cases import descriptor, path, read_descriptor
from native_mkdir_cases import exchange
from native_plan import close, connect, eof, login, packet, payload, read, send
from native_transfer_cases import file_stream, resource_fork

ROOT = b"mothra-alias20"
BASE = path((ROOT,))
DATA = b"alias-target\r\n\0\xff"
FILES = [
    (b"file", (), DATA, resource_fork(), b"TEXT", b"MOTH", b"alias-comment"),
    (b"empty", (), b"", b"", b"TEXT", b"MOTH", b""),
    (b"zero-tags", (), b"zero-tags", b"", bytes(4), bytes(4), b""),
    (b"unknown-tags", (), b"unknown-data", b"", b"XxYz", b"ZzQq", b"unknown-comment"),
    (b"same", (), b"same-source", b"", b"TEXT", b"MOTH", b"source-comment"),
    (b"self", (), b"self-source", b"", b"TEXT", b"MOTH", b"self-comment"),
    (b"hi-\x9a", (), b"high", b"", b"TEXT", b"MOTH", b""),
    *[
        (name, (), b"default-target", b"", b"TEXT", b"MOTH", b"")
        for name in [b"m-al20-absent", b"m-al20-empty", b"m-al20-zero"]
    ],
    (b"leaf", (b"dir",), b"dir-leaf", b"", b"TEXT", b"MOTH", b""),
    (
        b"same",
        (b"C",),
        b"collision-destination",
        b"",
        b"TEXT",
        b"MOTH",
        b"destination-comment",
    ),
    (b"keep", (b"C", b"dir"), b"keep", b"", b"TEXT", b"MOTH", b""),
]


def body(
    data: bytes, resource: bytes, kind: bytes, creator: bytes, comment: bytes
) -> bytes:
    """Build a file transfer body from a data fork, a resource fork, type, creator and comment."""
    forks = decode(file_stream(data, resource))
    info = bytearray(forks["INFO"])
    info[4:12] = kind + creator
    info[16:20] = bytes(4)
    offset = 72 + int.from_bytes(info[70:72], "big")
    info = info[:offset] + len(comment).to_bytes(2, "big") + comment
    return (
        b"FILP\0\1"
        + bytes(16)
        + b"\0\3"
        + b"".join(
            tag + bytes(8) + len(value).to_bytes(4, "big") + value
            for tag, value in [
                (b"INFO", bytes(info)),
                (b"DATA", data),
                (b"MACR", resource),
            ]
        )
    )


def upload(
    identifier: int, name: bytes, parent: tuple[bytes, ...], value: bytes
) -> list[dict]:
    """Build the steps that upload a file with the given name, parent and content."""
    channel, reference = f"up{identifier}", f"ref{identifier}"
    return [
        send(
            packet(
                203,
                identifier,
                payload(
                    [
                        (201, name),
                        (202, path((ROOT, *parent))),
                        (108, len(value).to_bytes(4, "big")),
                    ]
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
    """Build the plan that creates the alias capture's folders and files."""
    steps = login() + exchange(200, 9, [(202, b"\0\0")])
    for identifier, parts in enumerate(
        [
            (ROOT,),
            (ROOT, b"A"),
            (ROOT, b"B"),
            (ROOT, b"C"),
            (ROOT, b"D"),
            (ROOT, b"dir"),
            (ROOT, b"C", b"dir"),
        ],
        10,
    ):
        steps += exchange(205, identifier, [(201, parts[-1]), (202, path(parts[:-1]))])
    for identifier, (name, parent, data, resource, kind, creator, comment) in enumerate(
        FILES, 30
    ):
        steps += upload(
            identifier, name, parent, body(data, resource, kind, creator, comment)
        )
    steps += exchange(200, 60, [(202, BASE)]) + [close()]
    return {"seed-owned-alias-tree": (steps, {"kind": "alias-seed"})}


def specs() -> list[dict]:
    """Return the alias creation cases, each with its name, source, destination and role."""
    result = []

    def add(
        label: str,
        name: bytes | None,
        source: tuple[bytes, ...],
        destination: bytes | None,
        view: tuple[bytes, ...],
        target: bytes,
        *,
        role: str = "admin",
        extra: bool = False,
    ) -> None:
        """Append one alias creation case to the list."""
        result.append(
            {
                "case": label,
                "name_hex": None if name is None else name.hex(),
                "source_hex": path(source).hex(),
                "destination_hex": None if destination is None else destination.hex(),
                "view_hex": path(view).hex(),
                "target_hex": target.hex(),
                "role": role,
                "extra211": extra,
            }
        )

    for label, name, source, dest, extra in [
        ("live-file", b"file", (ROOT,), b"A", True),
        ("live-directory", b"dir", (ROOT,), b"A", False),
        ("file-alias-chain", b"file", (ROOT, b"A"), b"B", False),
        ("directory-alias-chain", b"dir", (ROOT, b"A"), b"B", False),
        ("missing-source", b"missing", (ROOT,), b"D", False),
        ("missing-destination", b"file", (ROOT,), b"missing-parent", False),
        ("destination-not-directory", b"file", (ROOT,), b"file", False),
        ("file-collision", b"same", (ROOT,), b"C", False),
        ("directory-collision", b"dir", (ROOT,), b"C", False),
        ("same-location", b"self", (ROOT,), None, False),
        ("high-byte-source", b"hi-\x9a", (ROOT,), b"D", False),
    ]:
        view = (ROOT, dest) if dest in {b"A", b"B", b"C", b"D"} else (ROOT,)
        add(
            label,
            name,
            source,
            path((ROOT, dest)) if dest is not None else BASE,
            view,
            name,
            extra=extra,
        )
    add(
        "permission-new",
        b"unknown-tags",
        (ROOT,),
        path((ROOT, b"D")),
        (ROOT, b"D"),
        b"unknown-tags",
        role="low",
    )
    add(
        "permission-conflict",
        b"file",
        (ROOT,),
        path((ROOT, b"A")),
        (ROOT, b"A"),
        b"file",
        role="low",
    )
    for label, name, destination in [
        ("destination-absent", b"m-al20-absent", None),
        ("destination-empty", b"m-al20-empty", b""),
        ("destination-root", b"m-al20-zero", b"\0\0"),
    ]:
        add(label, name, (ROOT,), destination, (), name)
    for label, name, source, target in [
        ("source-name-absent", None, b"file", b"derived-link"),
        ("source-name-empty", b"", b"file", b"derived-empty"),
        ("directory-name-absent", None, b"dir", b"derived-dir"),
    ]:
        add(
            label,
            name,
            (ROOT, source),
            path((ROOT, b"D", target)),
            (ROOT, b"D"),
            target,
        )
    return result


def create() -> dict:
    """Build one plan per case that attempts to create an alias, including the missing-source and permission cases, and reads the folders around it."""
    result = {}
    for expected in specs():
        steps = login()
        if expected["role"] == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        values = [(202, bytes.fromhex(expected["source_hex"]))]
        if expected["name_hex"] is not None:
            values.insert(0, (201, bytes.fromhex(expected["name_hex"])))
        before_source = list(values)
        if expected["destination_hex"] is not None:
            values.append((212, bytes.fromhex(expected["destination_hex"])))
        if expected["extra211"]:
            values.append((211, b"ignored-alias-name"))
        view = bytes.fromhex(expected["view_hex"])
        steps += exchange(200, 10, [(202, view)]) + exchange(206, 11, before_source)
        steps += exchange(209, 12, values)
        steps += (
            exchange(
                206, 13, [(201, bytes.fromhex(expected["target_hex"])), (202, view)]
            )
            + exchange(200, 14, [(202, view)])
            + exchange(500, 90, [])
        )
        steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
        result[expected["case"]] = (steps, {"kind": "alias-create", **expected})
    return result


def information() -> dict:
    """Build one plan per location that reads file information for ordinary files and folders, aliases and alias chains."""
    locations = [
        ("ordinary-file", b"file", (ROOT,)),
        ("empty-file", b"empty", (ROOT,)),
        ("zero-tags", b"zero-tags", (ROOT,)),
        ("unknown-tags", b"unknown-tags", (ROOT,)),
        ("ordinary-directory", b"dir", (ROOT,)),
        ("file-alias", b"file", (ROOT, b"A")),
        ("directory-alias", b"dir", (ROOT, b"A")),
        ("file-chain", b"file", (ROOT, b"B")),
        ("directory-chain", b"dir", (ROOT, b"B")),
        ("derived-alias", b"derived-link", (ROOT, b"D")),
        ("self-after-create", b"self", (ROOT,)),
    ]
    result = {}
    for label, name, parts in locations:
        steps = (
            login()
            + exchange(206, 10, [(201, name), (202, path(parts))])
            + exchange(200, 11, [(202, path(parts))])
            + exchange(500, 90, [])
            + [close()]
        )
        result[label] = (
            steps,
            {
                "kind": "alias-info",
                "name_hex": name.hex(),
                "parent_hex": path(parts).hex(),
            },
        )
    return result


def downloads() -> dict:
    """Build one plan per case that downloads a file or folder through an alias."""
    result = {}
    for label, name, parent, folder in [
        ("file-alias", b"file", (ROOT, b"A"), False),
        ("file-chain", b"file", (ROOT, b"B"), False),
        ("derived-alias", b"derived-link", (ROOT, b"D"), False),
        ("directory-alias", b"dir", (ROOT, b"A"), True),
        ("directory-chain", b"dir", (ROOT, b"B"), True),
    ]:
        steps = login() + [
            send(
                packet(
                    210 if folder else 202,
                    10,
                    payload([(201, name), (202, path(parent))]),
                )
            ),
            read(
                match_frame={"is_reply": 1, "id": 10},
                save_fields={"reference": 107, "size": 108},
            ),
            connect("transfer", "data"),
            send(
                "48545846{reference}"
                + ("0000000000010000" if folder else "0000000000000000"),
                "transfer",
            ),
        ]
        if folder:
            descriptor_steps = [
                {**s, "connection": "transfer"} for s in read_descriptor(0)
            ]
            descriptor_steps[-1]["expect_hex"] = descriptor((b"leaf",), False)[2:].hex()
            steps += descriptor_steps + [
                send("0001", "transfer"),
                {
                    "op": "read",
                    "connection": "transfer",
                    "size": 4,
                    "save": {"name": "body_size", "offset": 0, "size": 4},
                    "timeout": 30,
                },
                {
                    "op": "read",
                    "connection": "transfer",
                    "size_from": "body_size",
                    "timeout": 30,
                },
                send("0003", "transfer"),
                eof("transfer"),
            ]
        else:
            cancellation = packet(214, 11, payload([(107, b"REF!")])).replace(
                b"REF!".hex(), "{reference}"
            )
            steps += [
                {
                    "op": "read",
                    "connection": "transfer",
                    "size_from": "size",
                    "timeout": 30,
                },
                {"op": "expect_quiet", "connection": "transfer", "timeout": 3},
                send(cancellation),
                read(match_frame={"is_reply": 1, "id": 11}),
                eof("transfer"),
            ]
        steps += [close("transfer")] + exchange(500, 90, []) + [close()]
        result[label] = (
            steps,
            {
                "kind": "alias-download",
                "folder": folder,
                "name_hex": name.hex(),
                "parent_hex": path(parent).hex(),
            },
        )
    return result


def damage() -> dict:
    """Retain a fresh unresolved chain before repeating an existing alias target."""
    stage = (
        login()
        + exchange(
            209,
            10,
            [(201, b"file"), (202, path((ROOT, b"A"))), (212, path((ROOT, b"D")))],
        )
        + exchange(500, 90, [])
        + [close()]
    )
    steps, original = create()["live-file"]
    repeated = (
        steps[:-4]
        + exchange(206, 15, [(201, b"file"), (202, path((ROOT, b"D")))])
        + steps[-4:]
    )
    return {
        "stage-unresolved-chain": (
            stage,
            {
                "kind": "alias-unresolved-chain",
                "scope": "No206orlistingofnewD/filebefore repeat operation; native209ACK andliveness only.",
            },
        ),
        "repeat-existing-alias": (
            repeated,
            {"kind": "alias-repeat", "source_case": original},
        ),
    }


def supplementary() -> dict:
    """Build the supplementary plans: a download name collision, an unattached alias and comment updates."""
    transfers = downloads()
    steps, _ = transfers["file-alias"]
    steps = [dict(s) for s in steps]
    steps[7] = send(
        packet(202, 10, payload([(201, b"same"), (202, path((ROOT, b"C")))]))
    )
    collision = (steps, {"kind": "alias-collision-download"})
    unattached = (
        login()
        + exchange(202, 10, [(201, b"self"), (202, BASE)])
        + exchange(500, 90, [])
        + [close()]
    )
    comment = login()
    for identifier, value in [
        (20, b"directory-comment"),
        (30, b""),
        (40, b"directory-comment"),
        (50, b"\0"),
    ]:
        comment += exchange(207, identifier, [(201, b"dir"), (202, BASE), (210, value)])
        comment += exchange(206, identifier + 1, [(201, b"dir"), (202, BASE)])
        comment += exchange(
            206, identifier + 2, [(201, b"dir"), (202, path((ROOT, b"A")))]
        )
    comment += exchange(500, 90, []) + [close()]
    flush = (
        login()
        + upload(80, b"flush", (), body(b"", b"", b"TEXT", b"MOTH", b""))
        + exchange(200, 90, [(202, BASE)])
        + [close()]
    )
    return {
        "collision-alias-download": collision,
        "unattached-download-rejected": (
            unattached,
            {"kind": "alias-unattached-download"},
        ),
        "directory-comment-through-alias": (
            comment,
            {"kind": "alias-directory-comment"},
        ),
        "flush-owned-tree": (flush, {"kind": "alias-flush"}),
    }


def cleanup() -> dict:
    """Build the plan that requests moving the owned tree and three other named entries to Trash."""
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    names = [ROOT, b"m-al20-absent", b"m-al20-empty", b"m-al20-zero"]
    for identifier, name in enumerate(names, 20):
        steps += exchange(204, identifier, [(201, name)])
    steps += exchange(200, 90, [(202, b"\0\0")]) + exchange(500, 91, []) + [close()]
    return {
        "cleanup-owned-alias-tree": (
            steps,
            {"kind": "alias-cleanup", "names_hex": [n.hex() for n in names]},
        )
    }
