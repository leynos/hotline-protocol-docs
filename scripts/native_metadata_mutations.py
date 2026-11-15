"""Plan the owned-entry mutations, comment boundaries and empty-field cases.

Each planner returns the keyed plans that the native metadata corpus runs; the
verifier reads the same keys back. The table of account writes is in
native_metadata_specs.
"""

import typing as typ

from native_auth_cases import authentication
from native_metadata_specs import specs
from native_metadata_steps import (
    ACCOUNTS,
    BASE,
    EMPTY_PATH,
    FIELD_COMMENT,
    FIELD_NEW_NAME,
    PASSWORD,
    Cases,
    main_silence,
    upload,
)
from native_mkdir_cases import exchange
from native_plan import Action, close, login
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    TYPE_CREATE_FOLDER,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
    TYPE_SET_FILE_INFO,
)

LOGIN_REQUEST_INDEX = 3  # login() sends its login request as the fourth step
COMMENT_BOUNDARY_SIZES = [0, 1, 198, 199, 200, 201, 254, 255, 256, 300, 65535]
COMBINED_CASES: list[tuple[str, bool, bytes]] = [
    ("empty-name-new-comment", False, b"new-comment"),
    ("both-empty", False, b""),
    ("new-name-empty-comment", True, b""),
]


def mutation_steps(spec: dict[str, typ.Any]) -> list[Action]:
    """Plan one account-write case: the login, the write and the observations.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps; a role other than administrator logs in as its own account.
    """
    steps = login()
    if spec["role"] != "admin":
        steps[LOGIN_REQUEST_INDEX] = authentication(ACCOUNTS[spec["role"]][0], PASSWORD)
    name = bytes.fromhex(spec["name_hex"])
    values = [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, BASE)]
    steps += exchange(TYPE_GET_FILE_INFO, 10, values)
    steps += exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, BASE)])
    updates = list(values)
    for field, key in [(FIELD_COMMENT, "comment_hex"), (FIELD_NEW_NAME, "new_hex")]:
        if spec[key] is not None:
            updates.append((field, bytes.fromhex(spec[key])))
    steps += exchange(TYPE_SET_FILE_INFO, 12, updates)
    # Both names are observed, so an error cannot hide a partial rename.
    steps += exchange(TYPE_GET_FILE_INFO, 20, values)
    new = name if not spec["new_hex"] else bytes.fromhex(spec["new_hex"])
    steps += exchange(
        TYPE_GET_FILE_INFO, 21, [(FIELD_FILE_NAME, new), (FIELD_FILE_PATH, BASE)]
    )
    steps += exchange(TYPE_LIST_FILES, 22, [(FIELD_FILE_PATH, BASE)])
    steps += exchange(TYPE_EMPTY_ACK, 90, [])
    steps += [main_silence(), close()]
    return steps


def mutations() -> Cases:
    """Plan every account-write case of the table, keyed by its case name.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The steps and the expectation of each row of ``specs``.
    """
    result = {}
    for spec in specs():
        result[spec["case"]] = (
            mutation_steps(spec),
            {"kind": "metadata-mutation", **spec},
        )
    return result


def boundaries() -> Cases:
    """Plan the comment-size boundaries of a file and of a folder.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The file case and the folder case, each with its writes and readbacks.
    """
    result = {}
    sizes = list(COMMENT_BOUNDARY_SIZES)
    for label, name in [("file", b"f15"), ("dir", b"d15")]:
        steps = login() + exchange(
            TYPE_GET_FILE_INFO, 10, [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, BASE)]
        )
        for index, size in enumerate(sizes):
            identifier = 100 + 2 * index
            steps += exchange(
                TYPE_SET_FILE_INFO,
                identifier,
                [
                    (FIELD_FILE_NAME, name),
                    (FIELD_FILE_PATH, BASE),
                    (FIELD_COMMENT, b"x" * size),
                ],
            )
            steps += exchange(
                TYPE_GET_FILE_INFO,
                identifier + 1,
                [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, BASE)],
            )
        steps += [*exchange(TYPE_EMPTY_ACK, 90, []), close()]
        result[label] = (
            steps,
            {
                "kind": "metadata-comment-boundaries",
                "name_hex": name.hex(),
                "sizes": sizes,
            },
        )
    return result


def combined_steps(
    name: bytes, new: bytes, comment: bytes, *, folder: bool
) -> list[Action]:
    """Plan one combined empty-field case: create, write, rename and clean up.

    Returns
    -------
    list[dict[str, typing.Any]]
        The steps. The rename field is sent only when ``new`` differs from ``name``.
    """
    values = [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, EMPTY_PATH)]
    steps = login() + exchange(TYPE_LIST_FILES, 9, [(FIELD_FILE_PATH, EMPTY_PATH)])
    if folder:
        steps += exchange(TYPE_CREATE_FOLDER, 30, [(FIELD_FILE_NAME, name)])
        steps += exchange(
            TYPE_SET_FILE_INFO, 31, [*values, (FIELD_COMMENT, b"base-comment")]
        )
    else:
        steps += upload(30, name, EMPTY_PATH)
    steps += exchange(TYPE_GET_FILE_INFO, 10, values)
    steps += exchange(
        TYPE_SET_FILE_INFO,
        12,
        [
            *values,
            (FIELD_NEW_NAME, new if new != name else b""),
            (FIELD_COMMENT, comment),
        ],
    )
    steps += exchange(TYPE_GET_FILE_INFO, 20, values)
    steps += exchange(
        TYPE_GET_FILE_INFO, 21, [(FIELD_FILE_NAME, new), (FIELD_FILE_PATH, EMPTY_PATH)]
    )
    steps += exchange(TYPE_LIST_FILES, 22, [(FIELD_FILE_PATH, EMPTY_PATH)])
    steps += exchange(TYPE_DELETE_FILE, 40, [(FIELD_FILE_NAME, new)])
    steps += exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)])
    steps += exchange(TYPE_EMPTY_ACK, 91, [])
    steps += [main_silence(), close()]
    return steps


def combined_empty() -> Cases:
    """Plan the empty name and comment combinations that the table omits.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        One file case and one folder case for each combination, keyed by kind.
    """
    result = {}
    for folder in [False, True]:
        for label, rename, comment in COMBINED_CASES:
            key = ("dir-" if folder else "file-") + label
            name = b"m-m21-" + (b"d" if folder else b"f") + str(len(result)).encode()
            new = name + b"-new" if rename else name
            result[key] = (
                combined_steps(name, new, comment, folder=folder),
                {
                    "kind": "metadata-combined-empty",
                    "folder": folder,
                    "name_hex": name.hex(),
                    "final_hex": new.hex(),
                    "comment_hex": comment.hex(),
                },
            )
    return result
