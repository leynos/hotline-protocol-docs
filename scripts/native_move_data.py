"""Name the owned paths, constants and case tables of the native move planners.

native_move_cases re-exports every name here, so the verifiers and the moves test
import ROOT, COMMENT, move_specs and deletion_specs through native_move_cases.
"""

import typing as typ

from native_folder_cases import path

__all__ = [
    "AUTH_STEP_INDEX",
    "BASE",
    "COMMENT",
    "DATA",
    "DESTINATION",
    "EMPTY_PATH",
    "NAME_INDEX_WIDTH",
    "QUIET_TIMEOUT",
    "ROOT",
    "SECOND_PATH_FIELD",
    "SOURCE",
    "deletion_specs",
    "move_specs",
]

ROOT = b"mothra-fs22"
BASE = path((ROOT,))
SOURCE = path((ROOT, b"S"))
DESTINATION = path((ROOT, b"D"))
DATA = b"move-source\r\n\0\xff"
COMMENT = b"move-comment"
# The empty path, which the planners use for the Files root.
EMPTY_PATH = b"\0\0"
# The second path field of a request that names two paths, after field 202.
SECOND_PATH_FIELD = 212
# The digits of a case's index in the name of its entry.
NAME_INDEX_WIDTH = 2
# The index in login() of the step that a low-permission case replaces.
AUTH_STEP_INDEX = 3
# The timeout, in seconds, of the quiet window that closes each case.
QUIET_TIMEOUT = 1


def _named_destination(label: str) -> bytes:
    """Choose the destination of a move case that names a fixed path.

    Parameters
    ----------
    label : str
        The case label.

    Returns
    -------
    bytes
        The destination path; the destination folder for any other label.
    """
    match label:
        case "missing-destination":
            return path((ROOT, b"missing"))
        case "destination-file":
            return path((ROOT, b"destination-file"))
        case "alias-destination":
            return path((ROOT, b"D-alias"))
        case _:
            return DESTINATION


def _empty_destination(label: str) -> bytes | None:
    """Choose the destination of a case whose destination is absent, empty or root.

    Parameters
    ----------
    label : str
        One of the three labels ending in ``absent``, ``empty`` or ``root``.

    Returns
    -------
    bytes | None
        ``None`` when the destination is absent, ``b""`` when it is empty, and the
        empty path for the root.
    """
    match label:
        case "destination-absent":
            return None
        case "destination-empty":
            return b""
        case _:
            return EMPTY_PATH


def _case_destination(label: str, name: bytes) -> tuple[bytes | None, bytes]:
    """Choose the destination and the view address of one move case.

    Parameters
    ----------
    label : str
        The case label.
    name : bytes
        The name of the moved entry, which the cases inside the entry use.

    Returns
    -------
    tuple[bytes | None, bytes]
        The destination, which is ``None`` when absent, and the view address.
    """
    match label:
        case "same-parent":
            return SOURCE, SOURCE
        case "destination-absent" | "destination-empty" | "destination-root":
            return _empty_destination(label), EMPTY_PATH
        case "own-child":
            view = path((ROOT, b"S", name, b"child"))
            return view, view
        case "own-self":
            view = path((ROOT, b"S", name))
            return view, view
        case _:
            return _named_destination(label), DESTINATION


def move_specs() -> list[dict[str, typ.Any]]:
    """Describe the move cases for a file and for a folder, in their fixed order.

    Returns
    -------
    list[dict[str, typing.Any]]
        One description of each case: its name, label, role and addresses.
    """
    result: list[dict[str, typ.Any]] = []
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
                + str(index).encode().rjust(NAME_INDEX_WIDTH, b"0")
            )
            destination, view = _case_destination(label, name)
            result.append({
                "case": ("dir-" if folder else "file-") + label,
                "label": label,
                "name_hex": name.hex(),
                "folder": folder,
                "destination_hex": None if destination is None else destination.hex(),
                "view_hex": view.hex(),
                "role": "low" if label == "low-permission" else "admin",
            })
    return result


def deletion_specs() -> list[dict[str, typ.Any]]:
    """Describe the deletion cases, with their entries, parents and roles.

    Returns
    -------
    list[dict[str, typing.Any]]
        One description of each deletion case.
    """
    result: list[dict[str, typ.Any]] = []
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
        result.append({
            "case": label,
            "name_hex": None if name is None else name.hex(),
            "parent_hex": parent.hex(),
            "role": role,
        })
    return result
