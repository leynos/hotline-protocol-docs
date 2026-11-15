"""Prepare owned native directory creation and path-boundary observations."""

import typing as typ

from native_auth_cases import authentication
from native_folder_cases import path
from native_mkdir_specs import specs
from native_mkdir_steps import BASE, EMPTY_PATH, ROOT, Cases, exchange, upload
from native_plan import Action, close, login
from native_transfer_cases import file_stream
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    TYPE_CREATE_FOLDER,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
)

# prepare_native_cases imports the seed, creation, finalization, cleanup and
# empty_root planners; verify_native_mkdir imports those with BASE, ROOT and
# specs; and the account, alias, move, news, room, diagnostic, bitmap, metadata
# and verify_native_aliases modules import exchange. test_native_mkdir imports
# specs.
__all__ = [
    "BASE",
    "ROOT",
    "cleanup",
    "creation",
    "empty_root",
    "exchange",
    "finalization",
    "seed",
    "specs",
]

EMPTY_VIEW_HEX = "0000"  # the view of a zero-component path (the count word)
LOW_ROLE_STEP = 3  # the login request that follows the handshake steps
QUIET_SECONDS = 1


def quiet_main() -> Action:
    """Plan a one-second silence on the main connection.

    Returns
    -------
    native_plan.Action
        The ``expect_quiet`` action.
    """
    return {"op": "expect_quiet", "connection": "main", "timeout": QUIET_SECONDS}


def seed() -> Cases:
    """Plan the owned root, its folders and one uploaded file.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one seeding case.
    """
    steps = login() + exchange(TYPE_LIST_FILES, 9, [(FIELD_FILE_PATH, EMPTY_PATH)])
    for identifier, name, parent in [
        (10, ROOT, EMPTY_PATH),
        (11, b"exists", BASE),
        (12, b"nest", BASE),
        (13, b"leaf", path((ROOT, b"nest"))),
    ]:
        steps += exchange(
            TYPE_CREATE_FOLDER,
            identifier,
            [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, parent)],
        )
    body = file_stream(b"mkdir-fixture", b"")
    steps += upload(
        14,
        [(FIELD_FILE_NAME, b"ordinary"), (FIELD_FILE_PATH, BASE)],
        body,
    )
    steps += [*exchange(TYPE_LIST_FILES, 15, [(FIELD_FILE_PATH, BASE)]), close()]
    return {"seed-owned-root": (steps, {"kind": "mkdir-seed", "root_hex": ROOT.hex()})}


def creation() -> Cases:
    """Plan each directory-creation case with its readbacks and its login role.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and expectation of each case, by its label.
    """
    cases: Cases = {}
    for expected in specs():
        steps = login()
        if expected["role"] == "low":
            steps[LOW_ROLE_STEP] = authentication(b"fixture-low", b"next-pass")
        view = bytes.fromhex(expected["view_hex"])
        values: list[tuple[int, bytes]] = []
        for field, key in [
            (FIELD_FILE_NAME, "name_hex"),
            (FIELD_FILE_PATH, "path_hex"),
        ]:
            if expected[key] is not None:
                values.append((field, bytes.fromhex(expected[key])))
        steps += exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, view)])
        steps += exchange(TYPE_CREATE_FOLDER, 11, values)
        steps += exchange(TYPE_LIST_FILES, 12, [(FIELD_FILE_PATH, view)])
        steps += exchange(TYPE_EMPTY_ACK, 90, [])
        steps += [quiet_main(), close()]
        cases[expected["case"]] = (steps, {"kind": "mkdir-create", **expected})
    return cases


def finalization() -> Cases:
    """Plan the flush upload and the final inventory of the owned root.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one finalization case.
    """
    body = file_stream(b"", b"")
    steps = login() + upload(10, [(FIELD_FILE_NAME, b"m-fs19-flush")], body)
    for identifier, parts in [
        (20, ()),
        (21, (ROOT,)),
        (22, (ROOT, b"nest")),
        (23, (ROOT, b"nest", b"leaf")),
        (24, (ROOT, b".")),
        (25, (ROOT, b"..")),
        (26, (ROOT, b"co-lon")),
        (27, (ROOT, b"hi-\x9a")),
        (28, (ROOT, b"\0nul")),
    ]:
        steps += exchange(TYPE_LIST_FILES, identifier, [(FIELD_FILE_PATH, path(parts))])
    steps += (
        exchange(TYPE_GET_FILE_INFO, 30, [(FIELD_FILE_NAME, ROOT)])
        + exchange(
            TYPE_GET_FILE_INFO,
            31,
            [(FIELD_FILE_NAME, b"ordinary"), (FIELD_FILE_PATH, BASE)],
        )
        + [close()]
    )
    return {"final-inventory-and-flush": (steps, {"kind": "mkdir-final"})}


def cleanup() -> Cases:
    """Plan the removal of the owned objects and their readbacks.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one cleanup case.
    """
    names = (
        [ROOT]
        + [
            bytes.fromhex(c["name_hex"])
            for c in specs()
            if c["view_hex"] == EMPTY_VIEW_HEX
        ]
        + [b"m-fs19-flush"]
    )
    steps = login() + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, EMPTY_PATH)])
    for identifier, name in enumerate(names, 20):
        steps += exchange(TYPE_DELETE_FILE, identifier, [(FIELD_FILE_NAME, name)])
    steps += exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)])
    steps += [*exchange(TYPE_EMPTY_ACK, 91, []), quiet_main(), close()]
    return {
        "cleanup-owned-objects": (
            steps,
            {
                "kind": "mkdir-cleanup",
                "names_hex": [n.hex() for n in names],
                "scope": (
                    "Native204 moves owned objects to Trash; no permanent deletion "
                    "or root outside Files requested."
                ),
            },
        )
    }


def empty_root() -> Cases:
    """Check absent/empty names against absent/empty/canonical-root paths.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one empty-root case, with its input matrix in order.
    """
    steps = login() + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, EMPTY_PATH)])
    inputs: list[dict[str, typ.Any]] = []
    for name in [None, b""]:
        for parent in [None, b"", b"\0\0"]:
            values: list[tuple[int, bytes]] = []
            if name is not None:
                values.append((FIELD_FILE_NAME, name))
            if parent is not None:
                values.append((FIELD_FILE_PATH, parent))
            identifier = 20 + len(inputs)
            inputs.append({
                "id": identifier,
                "name_hex": None if name is None else name.hex(),
                "path_hex": None if parent is None else parent.hex(),
            })
            steps += exchange(TYPE_CREATE_FOLDER, identifier, values)
    steps += exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)])
    steps += [*exchange(TYPE_EMPTY_ACK, 91, []), quiet_main(), close()]
    return {
        "empty-root-input-matrix": (
            steps,
            {"kind": "mkdir-empty-root", "inputs": inputs},
        )
    }
