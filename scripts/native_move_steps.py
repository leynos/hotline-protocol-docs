"""Accumulate the seed steps of the native move corpus.

native_move_cases builds the seed with the Seeder below. The fixtures it creates are
the entries that the move and deletion cases act on, and their order is fixed.
"""

import typing as typ

from native_alias_cases import body
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_move_data import (
    BASE,
    COMMENT,
    DATA,
    DESTINATION,
    EMPTY_PATH,
    ROOT,
    SECOND_PATH_FIELD,
    SOURCE,
)
from native_plan import Action, login
from native_transfer_cases import resource_fork
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    TYPE_CREATE_FOLDER,
    TYPE_MAKE_ALIAS,
)

__all__ = ["Seeder"]


class Seeder:
    """Accumulate the seed steps and the request identifier of the next request."""

    def __init__(self) -> None:
        """Start the seed with the login that every seed step follows."""
        self.steps: list[Action] = login()
        self.counter = 100

    def folder(self, name: bytes, parent: bytes) -> None:
        """Plan the creation of a folder and advance the identifier.

        Parameters
        ----------
        name : bytes
            The name of the folder.
        parent : bytes
            The structured path of the folder that holds it.
        """
        self.steps += exchange(
            TYPE_CREATE_FOLDER,
            self.counter,
            [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, parent)],
        )
        self.counter += 1

    def file(self, name: bytes, parent: bytes, data: bytes = DATA) -> None:
        """Plan the upload of a file and advance the identifier.

        Parameters
        ----------
        name : bytes
            The name of the file.
        parent : bytes
            The structured path of the folder that holds it.
        data : bytes
            The data fork of the file.
        """
        self.steps += upload(
            self.counter,
            name,
            parent,
            body(data, resource_fork(), b"TEXT", b"MOTH", COMMENT),
        )
        self.counter += 1

    def add_move_source(self, spec: dict[str, typ.Any]) -> None:
        """Plan the entry that one move case moves, or its collision.

        Parameters
        ----------
        spec : dict[str, typing.Any]
            The description of the move case from ``move_specs``.
        """
        name, label = bytes.fromhex(spec["name_hex"]), spec["label"]
        if label == "missing-source":
            return
        if label == "alias-source":
            self.steps += exchange(
                TYPE_MAKE_ALIAS,
                self.counter,
                [
                    (FIELD_FILE_PATH, path((ROOT, b"S", b"alias-target"))),
                    (SECOND_PATH_FIELD, path((ROOT, b"S", name))),
                ],
            )
            self.counter += 1
        elif spec["folder"]:
            self.folder(name, SOURCE)
            self.folder(b"child", path((ROOT, b"S", name)))
            self.file(b"leaf", path((ROOT, b"S", name, b"child")), b"move-child")
        else:
            self.file(name, SOURCE)
        match label:
            case "file-collision":
                self.file(name, DESTINATION, b"collision-destination")
            case "folder-collision":
                self.folder(name, DESTINATION)

    def add_deletion_fixtures(self) -> None:
        """Plan the folders and files that the deletion cases remove."""
        for name in [
            b"del-nonempty",
            b"del-denied-dir",
            b"del-path-only",
            b"del-c1",
            b"del-c2",
        ]:
            self.folder(name, BASE)
            self.file(
                b"m-del22-dupe" if name.startswith(b"del-c") else b"leaf",
                path((ROOT, name)),
                b"delete-child-" + name,
            )
        for name in [b"del-file", b"del-denied-file", b"del-alias-target"]:
            self.file(name, BASE)

    def add_root_fixtures(self) -> None:
        """Plan the Files root and the folders and files beside the move sources."""
        self.folder(ROOT, EMPTY_PATH)
        self.folder(b"S", BASE)
        self.folder(b"D", BASE)
        self.file(b"destination-file", BASE, b"destination-file")
        self.file(b"alias-target", SOURCE)
