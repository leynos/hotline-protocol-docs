"""Prepare owned native moves, Trash operations and alias-resolution controls.

The names of the case tables and constants live in native_move_data, and the seed
builder in native_move_steps. They are re-exported here, so the consumers keep
importing them from this module: verify_native_moves, its checks and catalogue
modules and the moves test import COMMENT, ROOT, cleanup, deletion_specs,
deletions, finalization, move_specs, moves, preflight and seed, and
prepare_native_cases imports the planners.
"""

import typing as typ

from native_auth_cases import authentication
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_move_data import (
    AUTH_STEP_INDEX,
    BASE,
    COMMENT,
    DATA,
    DESTINATION,
    EMPTY_PATH,
    NAME_INDEX_WIDTH,
    QUIET_TIMEOUT,
    ROOT,
    SECOND_PATH_FIELD,
    SOURCE,
    deletion_specs,
    move_specs,
)
from native_move_steps import Seeder
from native_plan import Action, close, login
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_GET_ACCOUNT,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
    TYPE_MAKE_ALIAS,
    TYPE_MOVE_FILE,
)

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
    "Case",
    "Cases",
    "cleanup",
    "deletion_specs",
    "deletions",
    "finalization",
    "move_specs",
    "moves",
    "preflight",
    "seed",
]

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]


def preflight() -> Cases:
    """Plan the preflight of the move corpus: the listing and the low account.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The ``preflight`` plan with its expectation.
    """
    steps = [
        *login(),
        *exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, EMPTY_PATH)]),
        *exchange(TYPE_GET_ACCOUNT, 20, [(FIELD_LOGIN, b"fixture-low")]),
        close(),
    ]
    return {"preflight": (steps, {"kind": "move-preflight"})}


def seed() -> Cases:
    """Plan the seed that creates every fixture the move and deletion cases use.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The ``seed`` plan with its expectation.
    """
    seeder = Seeder()
    seeder.add_root_fixtures()
    for spec in move_specs():
        seeder.add_move_source(spec)
    seeder.steps += exchange(
        TYPE_MAKE_ALIAS,
        seeder.counter,
        [
            (FIELD_FILE_PATH, path((ROOT, b"D"))),
            (SECOND_PATH_FIELD, path((ROOT, b"D-alias"))),
        ],
    )
    # Deletion fixtures are separate from every move source/destination.
    seeder.add_deletion_fixtures()
    seeder.steps += exchange(
        TYPE_MAKE_ALIAS,
        seeder.counter + 10,
        [
            (FIELD_FILE_PATH, path((ROOT, b"del-alias-target"))),
            (SECOND_PATH_FIELD, path((ROOT, b"del-alias"))),
        ],
    )
    seeder.steps += [
        *exchange(TYPE_LIST_FILES, 900, [(FIELD_FILE_PATH, SOURCE)]),
        *exchange(TYPE_LIST_FILES, 901, [(FIELD_FILE_PATH, DESTINATION)]),
        close(),
    ]
    return {"seed": (seeder.steps, {"kind": "move-seed"})}


def moves() -> Cases:
    """Plan each move case: its listings, the move, and the reads after it.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        One ``move-case`` plan for each entry of ``move_specs``, keyed by case.
    """
    result: Cases = {}
    for spec in move_specs():
        name = bytes.fromhex(spec["name_hex"])
        view = bytes.fromhex(spec["view_hex"])
        steps = login()
        if spec["role"] == "low":
            steps[AUTH_STEP_INDEX] = authentication(b"fixture-low", b"next-pass")
        values = [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, SOURCE)]
        steps += exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, SOURCE)]) + exchange(
            TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, view)]
        )
        steps += exchange(TYPE_GET_FILE_INFO, 12, values)
        if spec["destination_hex"] is not None:
            values.append((SECOND_PATH_FIELD, bytes.fromhex(spec["destination_hex"])))
        steps += exchange(TYPE_MOVE_FILE, 13, values)
        steps += exchange(TYPE_LIST_FILES, 20, [(FIELD_FILE_PATH, SOURCE)]) + exchange(
            TYPE_LIST_FILES, 21, [(FIELD_FILE_PATH, view)]
        )
        steps += exchange(
            TYPE_GET_FILE_INFO, 22, [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, SOURCE)]
        ) + exchange(
            TYPE_GET_FILE_INFO, 23, [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, view)]
        )
        steps += [
            *exchange(TYPE_EMPTY_ACK, 90, []),
            {"op": "expect_quiet", "connection": "main", "timeout": QUIET_TIMEOUT},
            close(),
        ]
        result[spec["case"]] = (steps, {"kind": "move-case", **spec})
    return result


def deletions() -> Cases:
    """Plan each deletion case: its listings, the deletion, and the reads after it.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        One ``delete-case`` plan for each entry of ``deletion_specs``, by case.
    """
    result: Cases = {}
    for spec in deletion_specs():
        parent = bytes.fromhex(spec["parent_hex"])
        values = [(FIELD_FILE_PATH, parent)]
        if spec["name_hex"] is not None:
            values.insert(0, (FIELD_FILE_NAME, bytes.fromhex(spec["name_hex"])))
        steps = login()
        if spec["role"] == "low":
            steps[AUTH_STEP_INDEX] = authentication(b"fixture-low", b"next-pass")
        # Parent view stays addressable even when path-only selects the owned folder.
        view = BASE if spec["case"] == "path-only-directory" else parent
        steps += exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, view)]) + exchange(
            TYPE_GET_FILE_INFO, 11, values
        )
        steps += exchange(TYPE_DELETE_FILE, 12, values)
        steps += exchange(TYPE_LIST_FILES, 20, [(FIELD_FILE_PATH, view)]) + exchange(
            TYPE_GET_FILE_INFO, 21, values
        )
        if spec["case"] == "alias-target-to-trash":
            steps += exchange(
                TYPE_GET_FILE_INFO,
                30,
                [(FIELD_FILE_NAME, b"del-alias"), (FIELD_FILE_PATH, BASE)],
            )
        steps += [
            *exchange(TYPE_EMPTY_ACK, 90, []),
            {"op": "expect_quiet", "connection": "main", "timeout": QUIET_TIMEOUT},
            close(),
        ]
        result[spec["case"]] = (steps, {"kind": "delete-case", **spec})
    return result


def finalization() -> Cases:
    """Plan the final listing of the move corpus and the alias read.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The ``final`` plan with its expectation.
    """
    steps = login() + upload(80, b"flush", BASE)
    steps += (
        exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)])
        + exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, BASE)])
        + exchange(TYPE_LIST_FILES, 92, [(FIELD_FILE_PATH, SOURCE)])
        + exchange(TYPE_LIST_FILES, 93, [(FIELD_FILE_PATH, DESTINATION)])
    )
    steps += [
        *exchange(
            TYPE_GET_FILE_INFO,
            94,
            [(FIELD_FILE_NAME, b"del-alias"), (FIELD_FILE_PATH, BASE)],
        ),
        close(),
    ]
    return {"final": (steps, {"kind": "move-final"})}


def cleanup() -> Cases:
    """Plan the cleanup that removes the owned move entries from the Files root.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The ``cleanup`` plan, with the names it removes in its expectation.
    """
    steps = login() + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, EMPTY_PATH)])
    names = [ROOT] + [
        bytes.fromhex(s["name_hex"])
        for s in move_specs()
        if s["label"] in {"destination-absent", "destination-empty", "destination-root"}
    ]
    for identifier, name in enumerate(names, 20):
        steps += exchange(TYPE_DELETE_FILE, identifier, [(FIELD_FILE_NAME, name)])
    steps += [
        *exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)]),
        close(),
    ]
    return {
        "cleanup": (
            steps,
            {"kind": "move-cleanup", "names_hex": [n.hex() for n in names]},
        )
    }
