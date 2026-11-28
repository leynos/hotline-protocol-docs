"""Hold the news names, and the structure, body and cleanup cases of the news planner.

The planner in ``native_news_cases`` re-exports every name here, so that its
consumers keep importing ``structures``, ``bodies`` and the shared names from
that module.
"""

import typing as typ

from native_auth_cases import authentication
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import Action, close, login
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    TYPE_DELETE_FILE,
    TYPE_EMPTY_ACK,
    TYPE_LIST_FILES,
)

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

ROOT = b"mothra-news23"
BASE = path((ROOT,))
# The news transactions, and the fields of their requests (baseline-validity-ledger.md).
TYPE_LIST_NEWS_CATEGORIES = 370
TYPE_LIST_NEWS_ARTICLES = 371
TYPE_DELETE_NEWS_ITEM = 380
TYPE_CREATE_NEWS_FOLDER = 381
TYPE_CREATE_NEWS_CATEGORY = 382
TYPE_READ_NEWS_ARTICLE = 400
TYPE_POST_NEWS_ARTICLE = 410
FIELD_NEWS_NAME = 322
FIELD_NEWS_PATH = 325
FIELD_ARTICLE_ID = 326
FIELD_FLAVOUR = 327
FIELD_TITLE = 328
FIELD_BODY = 333
FIELD_FLAGS = 334
FIELD_RECURSIVE = 337
# The index of the login request in the steps that login() plans.
LOGIN_REQUEST_STEP = 3


def structures() -> Cases:
    """Plan the folder, category and deletion requests that the server must refuse.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        One structure case per label, in the order of the table of cases.
    """
    result: Cases = {}
    for label, kind, values, role in [
        (
            "folder-conflict-folder",
            TYPE_CREATE_NEWS_FOLDER,
            [(FIELD_FILE_NAME, b"bundle"), (FIELD_NEWS_PATH, BASE)],
            "admin",
        ),
        (
            "folder-conflict-category",
            TYPE_CREATE_NEWS_FOLDER,
            [(FIELD_FILE_NAME, b"category"), (FIELD_NEWS_PATH, BASE)],
            "admin",
        ),
        (
            "category-conflict-folder",
            TYPE_CREATE_NEWS_CATEGORY,
            [(FIELD_NEWS_NAME, b"bundle"), (FIELD_NEWS_PATH, BASE)],
            "admin",
        ),
        (
            "category-conflict-category",
            TYPE_CREATE_NEWS_CATEGORY,
            [(FIELD_NEWS_NAME, b"category"), (FIELD_NEWS_PATH, BASE)],
            "admin",
        ),
        (
            "folder-missing-parent",
            TYPE_CREATE_NEWS_FOLDER,
            [(FIELD_FILE_NAME, b"new"), (FIELD_NEWS_PATH, path((ROOT, b"missing")))],
            "admin",
        ),
        (
            "category-missing-parent",
            TYPE_CREATE_NEWS_CATEGORY,
            [(FIELD_NEWS_NAME, b"new"), (FIELD_NEWS_PATH, path((ROOT, b"missing")))],
            "admin",
        ),
        (
            "folder-category-parent",
            TYPE_CREATE_NEWS_FOLDER,
            [(FIELD_FILE_NAME, b"new"), (FIELD_NEWS_PATH, path((ROOT, b"category")))],
            "admin",
        ),
        (
            "category-category-parent",
            TYPE_CREATE_NEWS_CATEGORY,
            [(FIELD_NEWS_NAME, b"new"), (FIELD_NEWS_PATH, path((ROOT, b"category")))],
            "admin",
        ),
        (
            "folder-low-permission",
            TYPE_CREATE_NEWS_FOLDER,
            [(FIELD_FILE_NAME, b"new"), (FIELD_NEWS_PATH, BASE)],
            "low",
        ),
        (
            "category-low-permission",
            TYPE_CREATE_NEWS_CATEGORY,
            [(FIELD_NEWS_NAME, b"new"), (FIELD_NEWS_PATH, BASE)],
            "low",
        ),
        (
            "delete-low-folder",
            TYPE_DELETE_NEWS_ITEM,
            [(FIELD_NEWS_PATH, path((ROOT, b"bundle")))],
            "low",
        ),
        (
            "delete-low-category",
            TYPE_DELETE_NEWS_ITEM,
            [(FIELD_NEWS_PATH, path((ROOT, b"category")))],
            "low",
        ),
        (
            "delete-missing",
            TYPE_DELETE_NEWS_ITEM,
            [(FIELD_NEWS_PATH, path((ROOT, b"missing")))],
            "admin",
        ),
        ("delete-protected-news-root", TYPE_DELETE_NEWS_ITEM, [], "admin"),
    ]:
        steps = login()
        if role == "low":
            steps[LOGIN_REQUEST_STEP] = authentication(b"fixture-low", b"next-pass")
        steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 10, [(FIELD_NEWS_PATH, BASE)])
        steps += exchange(kind, 11, values)
        steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 12, [(FIELD_NEWS_PATH, BASE)])
        steps += exchange(TYPE_EMPTY_ACK, 90, [])
        steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
        result[label] = (
            steps,
            {"kind": "news-structure", "case": label, "request": kind, "role": role},
        )
    return result


def body_steps(fields: list[tuple[int, bytes]]) -> list[Action]:
    """Build one correlated body read followed by the liveness and quiet checks.

    Parameters
    ----------
    fields : list[tuple[int, bytes]]
        Ordered fields for the article read.

    Returns
    -------
    list[Action]
        Login, read, liveness barrier, quiet check and close.
    """
    return [
        *login(),
        *exchange(TYPE_READ_NEWS_ARTICLE, 10, fields),
        *exchange(TYPE_EMPTY_ACK, 90, []),
        {"op": "expect_quiet", "connection": "main", "timeout": 1},
        close(),
    ]


def read_presence(identifier: int) -> Cases:
    """Plan field-presence controls for an article identified by a prior listing.

    Parameters
    ----------
    identifier : int
        Public article ID from the fixture category listing.

    Returns
    -------
    Cases
        One separately capturable plan for each field and encoding.
    """
    result: Cases = {}
    for field in (FIELD_ARTICLE_ID, FIELD_FLAGS, FIELD_RECURSIVE):
        for shape, value in (("absent", None), ("empty", b""), ("zero", bytes(4))):
            fields = [(FIELD_NEWS_PATH, path((ROOT, b"category")))]
            article_id = (
                value if field == FIELD_ARTICLE_ID else identifier.to_bytes(4, "big")
            )
            if article_id is not None:
                fields.append((FIELD_ARTICLE_ID, article_id))
            fields.append((FIELD_FLAVOUR, b"text/plain"))
            if field != FIELD_ARTICLE_ID and value is not None:
                fields.append((field, value))
            result[f"{field}-{shape}"] = (
                body_steps(fields),
                {
                    "kind": "news-read-presence",
                    "field": field,
                    "encoding": shape,
                    "listed_article_id": identifier,
                },
            )
    return result


def bodies() -> Cases:
    """Plan the reads of the news bodies, including the invalid requests.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        One body case per label, in the order of the table of cases.
    """
    result: Cases = {}
    for label, identifier, flavour in [
        ("root-first", 1, b"text/plain"),
        ("root-second", 2, b"text/plain"),
        ("child-first", 4, b"text/plain"),
        ("child-second", 5, b"text/plain"),
        ("grandchild", 6, b"text/plain"),
        ("no-flavour", 3, b"text/plain"),
        ("unknown-flavour", 1, b"application/unknown"),
        ("flavour-case", 1, b"TEXT/PLAIN"),
        ("unknown-article", 99, b"text/plain"),
    ]:
        steps = body_steps([
            (FIELD_NEWS_PATH, path((ROOT, b"category"))),
            (FIELD_ARTICLE_ID, identifier.to_bytes(4, "big")),
            (FIELD_FLAVOUR, flavour),
        ])
        result[label] = (
            steps,
            {
                "kind": "news-body",
                "case": label,
                "id": identifier,
                "flavour_hex": flavour.hex(),
            },
        )
    return result


def finalization() -> Cases:
    """Plan the final listing after the upload that flushes the volume.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one final case, by its label.
    """
    steps = login() + exchange(TYPE_LIST_NEWS_CATEGORIES, 10, [(FIELD_NEWS_PATH, BASE)])
    # File upload supplies the previously verified native volume-flush path.
    steps += upload(80, b"m-news23-flush", b"\0\0")
    steps += [*exchange(TYPE_LIST_NEWS_CATEGORIES, 90, []), close()]
    return {"final": (steps, {"kind": "news-final"})}


def cleanup() -> Cases:
    """Plan the removal of the flushed upload, with its listings.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one cleanup case, by its label.
    """
    steps = login() + exchange(TYPE_DELETE_NEWS_ITEM, 10, [(FIELD_NEWS_PATH, BASE)])
    steps += exchange(TYPE_DELETE_FILE, 11, [(FIELD_FILE_NAME, b"m-news23-flush")])
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 90, []) + exchange(
        TYPE_EMPTY_ACK, 91, []
    )
    steps += [close()]
    return {"cleanup": (steps, {"kind": "news-cleanup"})}


def publish_cleanup() -> Cases:
    """Plan the upload that is published, and the file listings that follow it.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one publish case, by its label.
    """
    steps = login() + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, b"\0\0")])
    steps += upload(80, b"m-news23-publish", b"\0\0")
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 90, []) + exchange(
        TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")]
    )
    steps += [close()]
    return {"publish": (steps, {"kind": "news-publish-cleanup"})}


def remove_publisher() -> Cases:
    """Plan the removal of the published upload, and the listings that follow it.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one removal case, by its label.
    """
    steps = login() + exchange(
        TYPE_DELETE_FILE, 10, [(FIELD_FILE_NAME, b"m-news23-publish")]
    )
    steps += (
        exchange(TYPE_LIST_FILES, 90, [(FIELD_FILE_PATH, b"\0\0")])
        + exchange(TYPE_LIST_NEWS_CATEGORIES, 91, [])
        + exchange(TYPE_EMPTY_ACK, 92, [])
        + [close()]
    )
    return {"remove": (steps, {"kind": "news-remove-publisher"})}


def post_presence() -> Cases:
    """Plan root posts between two listings of the same disposable category.

    Returns
    -------
    Cases
        Nine independent sessions, one per field and encoding. The caller
        compares each new public article ID with its before-list inventory.
    """
    category = [(FIELD_NEWS_PATH, path((ROOT, b"category")))]
    result: Cases = {}
    for field in (FIELD_ARTICLE_ID, FIELD_FLAGS, FIELD_RECURSIVE):
        for shape, value in (("absent", None), ("empty", b""), ("zero", bytes(4))):
            fields = category.copy()
            if field == FIELD_ARTICLE_ID and value is not None:
                fields.append((field, value))
            fields.append((FIELD_TITLE, b"First root"))
            flags = value if field == FIELD_FLAGS else bytes(4)
            if flags is not None:
                fields.append((FIELD_FLAGS, flags))
            fields.extend([
                (FIELD_FLAVOUR, b"text/plain"),
                (FIELD_BODY, b"first-body\r\n\0\xff"),
            ])
            if field == FIELD_RECURSIVE and value is not None:
                fields.append((field, value))
            result[f"{field}-{shape}"] = (
                [
                    *login(),
                    *exchange(TYPE_LIST_NEWS_ARTICLES, 11, category),
                    *exchange(TYPE_POST_NEWS_ARTICLE, 20, fields),
                    *exchange(TYPE_LIST_NEWS_ARTICLES, 40, category),
                    *exchange(TYPE_EMPTY_ACK, 90, []),
                    {"op": "expect_quiet", "connection": "main", "timeout": 1},
                    close(),
                ],
                {"kind": "news-post-presence", "field": field, "encoding": shape},
            )
    return result
