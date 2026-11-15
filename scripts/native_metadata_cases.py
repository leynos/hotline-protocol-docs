"""Prepare owned rename/comment presence, privilege and partial-effect cases.

This module holds the preflight, seed, finalization and cleanup planners, and
re-exports the rest of the metadata planning from its helper modules.
"""

from native_auth_cases import complement
from native_metadata_mutations import boundaries, combined_empty, mutations
from native_metadata_specs import final_name, specs
from native_metadata_steps import (
    ACCOUNTS,
    BASE,
    EMPTY_PATH,
    FIELD_COMMENT,
    PASSWORD,
    ROOT,
    Cases,
    account_removal,
    upload,
)
from native_mkdir_cases import exchange
from native_plan import close, login
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    TYPE_CREATE_ACCOUNT,
    TYPE_CREATE_FOLDER,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_GET_ACCOUNT,
    TYPE_GET_FILE_INFO,
    TYPE_LIST_FILES,
    TYPE_SET_FILE_INFO,
)

# verify_native_metadata imports ACCOUNTS, ROOT, final_name, specs and the
# planners below; prepare_native_cases imports the planners under metadata_
# aliases; evidence-held run scripts import mutations and combined_empty; and
# the account, move, news and live-account cases import upload. The helpers
# are re-exported here so that every one of those names still imports from
# this module.
__all__ = [
    "ACCOUNTS",
    "BASE",
    "PASSWORD",
    "ROOT",
    "account_cleanup",
    "boundaries",
    "cleanup",
    "combined_empty",
    "final_name",
    "finalization",
    "mutations",
    "preflight",
    "seed",
    "specs",
    "upload",
]


def preflight() -> Cases:
    """Plan the check that the owned accounts and the owned tree are absent.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one preflight case.
    """
    steps = login() + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, EMPTY_PATH)])
    for identifier, (name, _) in enumerate(ACCOUNTS.values(), 20):
        steps += exchange(TYPE_GET_ACCOUNT, identifier, [(FIELD_LOGIN, name)])
    return {"preflight": ([*steps, close()], {"kind": "metadata-preflight"})}


def seed() -> Cases:
    """Plan the creation of the owned accounts, folders and files.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one seeding case.
    """
    steps = login()
    for identifier, (name, privileges) in enumerate(ACCOUNTS.values(), 20):
        steps += exchange(
            TYPE_CREATE_ACCOUNT,
            identifier,
            [
                (FIELD_LOGIN, complement(name)),
                (FIELD_PASSWORD, complement(PASSWORD)),
                (FIELD_NAME, name),
                (FIELD_ACCESS_BITMAP, privileges),
            ],
        )
        steps += exchange(TYPE_GET_ACCOUNT, identifier + 10, [(FIELD_LOGIN, name)])
    steps += exchange(TYPE_CREATE_FOLDER, 50, [(FIELD_FILE_NAME, ROOT)])
    steps += upload(60, b"occupied")
    for identifier, spec in enumerate(specs(), 100):
        name = bytes.fromhex(spec["name_hex"])
        if spec["folder"]:
            steps += exchange(
                TYPE_CREATE_FOLDER,
                identifier,
                [(FIELD_FILE_NAME, name), (FIELD_FILE_PATH, BASE)],
            )
            steps += exchange(
                TYPE_SET_FILE_INFO,
                identifier + 100,
                [
                    (FIELD_FILE_NAME, name),
                    (FIELD_FILE_PATH, BASE),
                    (FIELD_COMMENT, b"base-comment"),
                ],
            )
        else:
            steps += upload(identifier, name)
    steps += [*exchange(TYPE_LIST_FILES, 500, [(FIELD_FILE_PATH, BASE)]), close()]
    return {"seed": (steps, {"kind": "metadata-seed"})}


def finalization() -> Cases:
    """Plan the final read of every table row's name after its write.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one finalization case.
    """
    steps = login() + upload(80, b"flush")
    for identifier, spec in enumerate(specs(), 100):
        steps += exchange(
            TYPE_GET_FILE_INFO,
            identifier,
            [(FIELD_FILE_NAME, final_name(spec)), (FIELD_FILE_PATH, BASE)],
        )
    steps += exchange(TYPE_LIST_FILES, 500, [(FIELD_FILE_PATH, BASE)])
    steps += [*exchange(TYPE_EMPTY_ACK, 90, []), close()]
    return {"final": (steps, {"kind": "metadata-final"})}


def cleanup() -> Cases:
    """Plan the removal of the owned tree and of the owned accounts.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one cleanup case.
    """
    steps = login() + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, EMPTY_PATH)])
    steps += exchange(TYPE_DELETE_FILE, 20, [(FIELD_FILE_NAME, ROOT)])
    steps += account_removal()
    steps += exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)])
    return {"cleanup": ([*steps, close()], {"kind": "metadata-cleanup"})}


def account_cleanup() -> Cases:
    """Plan the removal of the owned accounts alone.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The one account-cleanup case.
    """
    steps = login() + account_removal()
    steps += exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, EMPTY_PATH)])
    return {"accounts": ([*steps, close()], {"kind": "metadata-account-cleanup"})}
