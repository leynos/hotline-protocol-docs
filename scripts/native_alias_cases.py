"""Prepare owned native aliases, metadata variants and resolved transfers."""

from native_alias_specs import Spec, create, specs
from native_alias_steps import BASE, DATA, FILES, ROOT, Case, body, upload
from native_folder_cases import descriptor, path, read_descriptor
from native_mkdir_cases import exchange
from native_plan import close, connect, eof, login, packet, payload, read, send

# Consumers: native_metadata_cases and native_move_cases import body; the evidence
# held sources do too. prepare_native_cases imports cleanup, create, damage,
# downloads, information, seed and supplementary under the alias_ prefix.
# verify_native_aliases and test_native_aliases import create and information.
__all__ = [
    "BASE",
    "DATA",
    "FILES",
    "ROOT",
    "Spec",
    "body",
    "cleanup",
    "create",
    "damage",
    "downloads",
    "information",
    "seed",
    "specs",
    "supplementary",
    "upload",
]


def seed() -> dict[str, Case]:
    """Plan the upload of the owned alias tree, from its folders and files.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of the seeding case.
    """
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
    steps += [*exchange(200, 60, [(202, BASE)]), close()]
    return {"seed-owned-alias-tree": (steps, {"kind": "alias-seed"})}


def information() -> dict[str, Case]:
    """Plan the information request of each alias, file and directory location.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each location.
    """
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


def downloads() -> dict[str, Case]:
    """Plan the download of each alias, through files and folders.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each download.
    """
    result = {}
    for label, name, parent, folder in [
        ("file-alias", b"file", (ROOT, b"A"), False),
        ("file-chain", b"file", (ROOT, b"B"), False),
        ("derived-alias", b"derived-link", (ROOT, b"D"), False),
        ("directory-alias", b"dir", (ROOT, b"A"), True),
        ("directory-chain", b"dir", (ROOT, b"B"), True),
    ]:
        steps = [
            *login(),
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
            descriptor_steps[-1]["expect_hex"] = descriptor(
                (b"leaf",), directory=False
            )[2:].hex()
            steps += [
                *descriptor_steps,
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
        steps += [close("transfer"), *exchange(500, 90, []), close()]
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


def damage() -> dict[str, Case]:
    """Retain a fresh unresolved chain before repeating an existing alias target.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The staging case and the repeated-alias case.
    """
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
                "scope": (
                    "No206orlistingofnewD/filebefore repeat operation; "
                    "native209ACK andliveness only."
                ),
            },
        ),
        "repeat-existing-alias": (
            repeated,
            {"kind": "alias-repeat", "source_case": original},
        ),
    }


def supplementary() -> dict[str, Case]:
    """Plan the download and comment cases that follow the alias creations.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The collision, unattached, comment and flush cases.
    """
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
    comment += [*exchange(500, 90, []), close()]
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


def cleanup() -> dict[str, Case]:
    """Plan the removal of the owned alias tree and the restoring listing.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of the cleanup case.
    """
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
