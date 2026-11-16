"""Prepare isolated article-deletion trees, scalar controls and native cleanup."""

import typing as typ

from native_auth_cases import authentication
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_news_delete_specs import BASE, NODES, ROOT, specs
from native_plan import Action, close, login
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_LOGIN,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_GET_ACCOUNT,
    TYPE_LIST_FILES,
)

# ROOT, BASE, NODES and specs live in native_news_delete_specs; the names below stay
# importable from this module. prepare_native_cases imports cleanup, deletions,
# finalization, inspect_seed, preflight, publish_cleanup, remove_publisher,
# resume_category, seed and seed_categories; verify_native_article_deletion
# imports the module; the test imports resume_category and specs; and the
# executed run-resume.py imports NODES and specs.
__all__ = [
    "BASE",
    "NODES",
    "ROOT",
    "cleanup",
    "deletions",
    "finalization",
    "initial_burst_seed",
    "inspect_seed",
    "preflight",
    "publish_cleanup",
    "remove_publisher",
    "resume_category",
    "seed",
    "seed_categories",
    "specs",
]

# Transaction types and field IDs of these plans. native_wire_names.py names
# some of the values used here, and those names are imported above. The others
# keep their numbers as names: no document in that file says what they mean.
TYPE_370 = 370
TYPE_371 = 371
TYPE_380 = 380
TYPE_381 = 381
TYPE_382 = 382
TYPE_400 = 400
TYPE_410 = 410
TYPE_411 = 411
FIELD_322 = 322
FIELD_325 = 325
FIELD_326 = 326
FIELD_327 = 327
FIELD_328 = 328
FIELD_333 = 333
FIELD_337 = 337

ID_BYTES = 4  # the width of a big-endian identifier field
LOW_ROLE_STEP = 3  # the index of the login request that a low role replaces
PAUSE_SECONDS = 3  # the pause that ends a resumed seed
QUIET_TIMEOUT_SECONDS = 3  # the expect_quiet timeout of a deletion plan
INVALID_PREFIX_MESSAGE = "Invalid owned category/prefix"

type Cases = dict[str, tuple[list[Action], dict[str, typ.Any]]]


def preflight() -> Cases:
    """Plan the preflight login, the root listing and the low-role login.

    Returns
    -------
    Cases
    """
    steps = [
        *login(),
        *exchange(TYPE_370, 10, []),
        *exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")]),
    ]
    steps += [
        *exchange(TYPE_GET_ACCOUNT, 12, [(FIELD_LOGIN, b"fixture-low")]),
        close(),
    ]
    return {"preflight": (steps, {"kind": "news-delete-preflight"})}


def initial_burst_seed() -> Cases:
    """Reconstruct the retained unpaced failed plan; never exposed by the CLI.

    Returns
    -------
    Cases
    """
    steps = [*login(), *exchange(TYPE_381, 10, [(FIELD_FILE_NAME, ROOT)])]
    counter = 100
    for spec in specs():
        name = spec["case"].encode()
        category = path((ROOT, name))
        steps += exchange(TYPE_382, counter, [(FIELD_322, name), (FIELD_325, BASE)])
        counter += 1
        for _, title, parent in NODES:
            steps += exchange(
                TYPE_410,
                counter,
                [
                    (FIELD_325, category),
                    (FIELD_326, parent.to_bytes(ID_BYTES, "big")),
                    (FIELD_328, title),
                    (FIELD_327, b"text/plain"),
                    (FIELD_333, b"body-" + title),
                ],
            )
            counter += 1
    steps += [*exchange(TYPE_370, 900, [(FIELD_325, BASE)]), close()]
    return {"seed": (steps, {"kind": "news-delete-seed"})}


def seed() -> Cases:
    """Plan the owned News root and its listing.

    Returns
    -------
    Cases
    """
    steps = [
        *login(),
        *exchange(TYPE_381, 10, [(FIELD_FILE_NAME, ROOT)]),
        *exchange(TYPE_370, 90, [(FIELD_325, BASE)]),
        close(),
    ]
    return {"root": (steps, {"kind": "news-delete-root"})}


def inspect_seed() -> Cases:
    """Plan the inventory of the owned categories after an interrupted seed.

    Returns
    -------
    Cases
    """
    steps = [*login(), *exchange(TYPE_370, 10, [(FIELD_325, BASE)])]
    for identifier, spec in enumerate(specs(), 100):
        steps += exchange(
            TYPE_371, identifier, [(FIELD_325, path((ROOT, spec["case"].encode())))]
        )
    steps += [*exchange(TYPE_EMPTY_ACK, 90, []), close()]
    return {"inventory": (steps, {"kind": "news-delete-inventory"})}


def resume_category(
    case: str,
    completed: int = 0,
    exists: bool = False,  # ruff: ignore[boolean-type-hint-positional-argument, boolean-default-value-positional-argument]  # the callers pass exists positionally
) -> Cases:
    """Plan the seeding of one owned category, resuming after a prefix.

    Parameters
    ----------
    case : str
        The name of an owned category from :func:`specs`.
    completed : int
        The number of articles of ``NODES`` that already exist.
    exists : bool
        Whether the category itself already exists.

    Returns
    -------
    Cases

    Raises
    ------
    ValueError
        If ``case`` is not an owned category, the prefix is out of range, or
        a prefix is given for a category that does not exist.
    """
    if case not in {s["case"] for s in specs()} or not 0 <= completed <= len(NODES):
        raise ValueError(INVALID_PREFIX_MESSAGE)
    if completed and not exists:
        raise ValueError(INVALID_PREFIX_MESSAGE)
    category = path((ROOT, case.encode()))
    steps = login()
    if exists:
        steps += exchange(TYPE_371, 10, [(FIELD_325, category)])
    else:
        steps += exchange(TYPE_382, 11, [(FIELD_322, case.encode()), (FIELD_325, BASE)])
    for identifier, (_, title, parent) in enumerate(NODES[completed:], 100):
        steps += exchange(
            TYPE_410,
            identifier,
            [
                (FIELD_325, category),
                (FIELD_326, parent.to_bytes(ID_BYTES, "big")),
                (FIELD_328, title),
                (FIELD_327, b"text/plain"),
                (FIELD_333, b"body-" + title),
            ],
        )
    steps += [
        *exchange(TYPE_371, 20, [(FIELD_325, category)]),
        {"op": "pause", "seconds": PAUSE_SECONDS},
        close(),
    ]
    return {
        case: (
            steps,
            {
                "kind": "news-delete-resume",
                "case": case,
                "completed": completed,
                "exists": exists,
            },
        )
    }


def seed_categories() -> Cases:
    """Plan the resumed seeding of every owned category.

    Returns
    -------
    Cases
    """
    result: Cases = {}
    for spec in specs():
        result.update(resume_category(spec["case"]))
    return result


def deletions() -> Cases:
    """Plan the deletion of each owned case, with its replies and quiet check.

    Returns
    -------
    Cases
    """
    result: Cases = {}
    for spec in specs():
        category = path((ROOT, spec["case"].encode()))
        values = [
            (
                FIELD_325,
                path((ROOT, b"missing")) if spec["missing_category"] else category,
            )
        ]
        if spec["article"] is not None:
            values.append((FIELD_326, spec["article"].to_bytes(ID_BYTES, "big")))
        if spec["value_hex"] is not None:
            values.append((FIELD_337, bytes.fromhex(spec["value_hex"])))
        steps = login()
        if spec["role"] == "low":
            steps[LOW_ROLE_STEP] = authentication(b"fixture-low", b"next-pass")
        steps += exchange(TYPE_371, 10, [(FIELD_325, category)])
        steps += exchange(TYPE_411, 11, values)
        if spec["repeat"]:
            steps += exchange(TYPE_411, 12, values)
        steps += [
            *exchange(TYPE_371, 20, [(FIELD_325, category)]),
            *exchange(TYPE_371, 21, [(FIELD_325, category)]),
        ]
        for identifier, _, _ in NODES if spec["role"] == "admin" else NODES[:1]:
            steps += exchange(
                TYPE_400,
                100 + identifier,
                [
                    (FIELD_325, category),
                    (FIELD_326, identifier.to_bytes(ID_BYTES, "big")),
                    (FIELD_327, b"text/plain"),
                ],
            )
        steps += [
            *exchange(TYPE_EMPTY_ACK, 90, []),
            {
                "op": "expect_quiet",
                "connection": "main",
                "timeout": QUIET_TIMEOUT_SECONDS,
            },
            close(),
        ]
        result[spec["case"]] = (steps, {"kind": "news-delete", **spec})
    return result


def finalization() -> Cases:
    """Plan the independent final listing, the denied bodies and the cleanup.

    Returns
    -------
    Cases
    """
    steps = [*login(), *upload(80, b"m-nd24-flush", b"\0\0")]
    for identifier, spec in enumerate(specs(), 100):
        steps += exchange(
            TYPE_371, identifier, [(FIELD_325, path((ROOT, spec["case"].encode())))]
        )
    for identifier, _, _ in NODES:
        steps += exchange(
            TYPE_400,
            500 + identifier,
            [
                (FIELD_325, path((ROOT, b"denied"))),
                (FIELD_326, identifier.to_bytes(ID_BYTES, "big")),
                (FIELD_327, b"text/plain"),
            ],
        )
    steps += [*exchange(TYPE_370, 900, [(FIELD_325, BASE)]), close()]
    return {"final": (steps, {"kind": "news-delete-final"})}


def cleanup() -> Cases:
    """Plan the removal of the flush file and the owned root.

    Returns
    -------
    Cases
    """
    steps = [
        *login(),
        *exchange(TYPE_380, 10, [(FIELD_325, BASE)]),
        *exchange(TYPE_DELETE_FILE, 11, [(FIELD_FILE_NAME, b"m-nd24-flush")]),
    ]
    steps += [
        *exchange(TYPE_370, 90, []),
        *exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")]),
        close(),
    ]
    return {"cleanup": (steps, {"kind": "news-delete-cleanup"})}


def publish_cleanup() -> Cases:
    """Plan the upload of the separate publisher file and its listing.

    Returns
    -------
    Cases
    """
    steps = [*login(), *upload(80, b"m-nd24-publish", b"\0\0")]
    steps += [
        *exchange(TYPE_370, 90, []),
        *exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")]),
        close(),
    ]
    return {"publish": (steps, {"kind": "news-delete-publish"})}


def remove_publisher() -> Cases:
    """Plan the removal of the separate publisher file and the listings.

    Returns
    -------
    Cases
    """
    steps = [
        *login(),
        *exchange(TYPE_DELETE_FILE, 10, [(FIELD_FILE_NAME, b"m-nd24-publish")]),
    ]
    steps += [
        *exchange(TYPE_370, 90, []),
        *exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")]),
        *exchange(TYPE_EMPTY_ACK, 92, []),
        close(),
    ]
    return {"remove": (steps, {"kind": "news-delete-remove-publisher"})}
