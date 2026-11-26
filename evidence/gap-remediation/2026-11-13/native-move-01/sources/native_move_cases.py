"""Prepare owned native moves, Trash operations and alias-resolution controls."""

from native_alias_cases import body
from native_auth_cases import authentication
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login
from native_transfer_cases import resource_fork

ROOT = b"mothra-fs22"
BASE = path((ROOT,))
SOURCE = path((ROOT, b"S"))
DESTINATION = path((ROOT, b"D"))
DATA = b"move-source\r\n\0\xff"
COMMENT = b"move-comment"


def move_specs() -> list[dict]:
    """Return the move cases for files and folders, each with its names, destination and role."""
    result = []
    for folder in [False, True]:
        labels = [
            "ordinary",
            "same-parent",
            "file-collision",
            "folder-collision",
            "missing-source",
            "missing-destination",
            "destination-file",
            "low-permission",
            "destination-absent",
            "destination-empty",
            "destination-root",
        ]
        if folder:
            labels += ["own-child", "own-self"]
        else:
            labels += ["alias-source", "alias-destination"]
        for index, label in enumerate(labels):
            name = (
                b"m-mv22-"
                + (b"d" if folder else b"f")
                + str(index).encode().rjust(2, b"0")
            )
            destination = DESTINATION
            view = DESTINATION
            if label == "same-parent":
                destination = view = SOURCE
            elif label in {
                "destination-absent",
                "destination-empty",
                "destination-root",
            }:
                destination = (
                    None
                    if label.endswith("absent")
                    else b""
                    if label.endswith("empty")
                    else b"\0\0"
                )
                view = b"\0\0"
            elif label == "missing-destination":
                destination = path((ROOT, b"missing"))
            elif label == "destination-file":
                destination = path((ROOT, b"destination-file"))
            elif label == "alias-destination":
                destination = path((ROOT, b"D-alias"))
            elif label == "own-child":
                destination = view = path((ROOT, b"S", name, b"child"))
            elif label == "own-self":
                destination = view = path((ROOT, b"S", name))
            result.append(
                {
                    "case": ("dir-" if folder else "file-") + label,
                    "label": label,
                    "name_hex": name.hex(),
                    "folder": folder,
                    "destination_hex": None
                    if destination is None
                    else destination.hex(),
                    "view_hex": view.hex(),
                    "role": "low" if label == "low-permission" else "admin",
                }
            )
    return result


def preflight() -> dict:
    """Build the plan that confirms the fixture state before the move capture."""
    steps = (
        login()
        + exchange(200, 10, [(202, b"\0\0")])
        + exchange(352, 20, [(105, b"fixture-low")])
        + [close()]
    )
    return {"preflight": (steps, {"kind": "move-preflight"})}


def seed() -> dict:
    """Build the plan that creates the folders and files the moves act on."""
    steps = login()
    counter = 100

    def folder(name: bytes, parent: bytes) -> None:
        """Append the steps that create one folder."""
        nonlocal counter, steps
        steps += exchange(205, counter, [(201, name), (202, parent)])
        counter += 1

    def file(name: bytes, parent: bytes, data: bytes = DATA) -> None:
        """Append the steps that upload one file with forks."""
        nonlocal counter, steps
        steps += upload(
            counter,
            name,
            parent,
            body(data, resource_fork(), b"TEXT", b"MOTH", COMMENT),
        )
        counter += 1

    folder(ROOT, b"\0\0")
    folder(b"S", BASE)
    folder(b"D", BASE)
    file(b"destination-file", BASE, b"destination-file")
    file(b"alias-target", SOURCE)
    for spec in move_specs():
        name, label = bytes.fromhex(spec["name_hex"]), spec["label"]
        if label == "missing-source":
            continue
        if label == "alias-source":
            steps += exchange(
                209,
                counter,
                [
                    (202, path((ROOT, b"S", b"alias-target"))),
                    (212, path((ROOT, b"S", name))),
                ],
            )
            counter += 1
        elif spec["folder"]:
            folder(name, SOURCE)
            folder(b"child", path((ROOT, b"S", name)))
            file(b"leaf", path((ROOT, b"S", name, b"child")), b"move-child")
        else:
            file(name, SOURCE)
        if label == "file-collision":
            file(name, DESTINATION, b"collision-destination")
        elif label == "folder-collision":
            folder(name, DESTINATION)
    steps += exchange(
        209, counter, [(202, path((ROOT, b"D"))), (212, path((ROOT, b"D-alias")))]
    )
    # Deletion fixtures are separate from every move source/destination.
    for name in [
        b"del-nonempty",
        b"del-denied-dir",
        b"del-path-only",
        b"del-c1",
        b"del-c2",
    ]:
        folder(name, BASE)
        file(
            b"m-del22-dupe" if name.startswith(b"del-c") else b"leaf",
            path((ROOT, name)),
            b"delete-child-" + name,
        )
    for name in [b"del-file", b"del-denied-file", b"del-alias-target"]:
        file(name, BASE)
    steps += exchange(
        209,
        counter + 10,
        [(202, path((ROOT, b"del-alias-target"))), (212, path((ROOT, b"del-alias")))],
    )
    steps += (
        exchange(200, 900, [(202, SOURCE)])
        + exchange(200, 901, [(202, DESTINATION)])
        + [close()]
    )
    return {"seed": (steps, {"kind": "move-seed"})}


def moves() -> dict:
    """Build one plan per move case that moves an item and reads both folders back."""
    result = {}
    for spec in move_specs():
        name = bytes.fromhex(spec["name_hex"])
        view = bytes.fromhex(spec["view_hex"])
        steps = login()
        if spec["role"] == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        values = [(201, name), (202, SOURCE)]
        steps += exchange(200, 10, [(202, SOURCE)]) + exchange(200, 11, [(202, view)])
        steps += exchange(206, 12, values)
        if spec["destination_hex"] is not None:
            values.append((212, bytes.fromhex(spec["destination_hex"])))
        steps += exchange(208, 13, values)
        steps += exchange(200, 20, [(202, SOURCE)]) + exchange(200, 21, [(202, view)])
        steps += exchange(206, 22, [(201, name), (202, SOURCE)]) + exchange(
            206, 23, [(201, name), (202, view)]
        )
        steps += exchange(500, 90, []) + [
            {"op": "expect_quiet", "connection": "main", "timeout": 1},
            close(),
        ]
        result[spec["case"]] = (steps, {"kind": "move-case", **spec})
    return result


def deletion_specs() -> list[dict]:
    """Return the deletion cases, each with its name, parent and role."""
    result = []
    for label, name, parent, role in [
        ("ordinary-file", b"del-file", BASE, "admin"),
        ("nonempty-directory", b"del-nonempty", BASE, "admin"),
        ("missing-source", b"no-such-delete", BASE, "admin"),
        ("denied-file", b"del-denied-file", BASE, "low"),
        ("denied-directory", b"del-denied-dir", BASE, "low"),
        ("path-only-directory", None, path((ROOT, b"del-path-only")), "admin"),
        ("trash-name-first", b"m-del22-dupe", path((ROOT, b"del-c1")), "admin"),
        ("trash-name-conflict", b"m-del22-dupe", path((ROOT, b"del-c2")), "admin"),
        ("alias-target-to-trash", b"del-alias-target", BASE, "admin"),
    ]:
        result.append(
            {
                "case": label,
                "name_hex": None if name is None else name.hex(),
                "parent_hex": parent.hex(),
                "role": role,
            }
        )
    return result


def deletions() -> dict:
    """Build one plan per deletion case that deletes an item and reads its folder back."""
    result = {}
    for spec in deletion_specs():
        parent = bytes.fromhex(spec["parent_hex"])
        values = [(202, parent)]
        if spec["name_hex"] is not None:
            values.insert(0, (201, bytes.fromhex(spec["name_hex"])))
        steps = login()
        if spec["role"] == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        # Parent view stays addressable even when path-only selects the owned folder.
        view = BASE if spec["case"] == "path-only-directory" else parent
        steps += exchange(200, 10, [(202, view)]) + exchange(206, 11, values)
        steps += exchange(204, 12, values)
        steps += exchange(200, 20, [(202, view)]) + exchange(206, 21, values)
        if spec["case"] == "alias-target-to-trash":
            steps += exchange(206, 30, [(201, b"del-alias"), (202, BASE)])
        steps += exchange(500, 90, []) + [
            {"op": "expect_quiet", "connection": "main", "timeout": 1},
            close(),
        ]
        result[spec["case"]] = (steps, {"kind": "delete-case", **spec})
    return result


def finalization() -> dict:
    """Build the plan that flushes and reads back every folder the cases touched."""
    steps = login() + upload(80, b"flush", BASE)
    steps += (
        exchange(200, 90, [(202, b"\0\0")])
        + exchange(200, 91, [(202, BASE)])
        + exchange(200, 92, [(202, SOURCE)])
        + exchange(200, 93, [(202, DESTINATION)])
    )
    steps += exchange(206, 94, [(201, b"del-alias"), (202, BASE)]) + [close()]
    return {"final": (steps, {"kind": "move-final"})}


def cleanup() -> dict:
    """Build the plan that deletes the owned folders."""
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    names = [ROOT] + [
        bytes.fromhex(s["name_hex"])
        for s in move_specs()
        if s["label"] in {"destination-absent", "destination-empty", "destination-root"}
    ]
    for identifier, name in enumerate(names, 20):
        steps += exchange(204, identifier, [(201, name)])
    steps += exchange(200, 90, [(202, b"\0\0")]) + [close()]
    return {
        "cleanup": (
            steps,
            {"kind": "move-cleanup", "names_hex": [n.hex() for n in names]},
        )
    }
