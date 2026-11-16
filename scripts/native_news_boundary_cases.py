"""Prepare paced, owned child-append boundary observations."""

import typing as typ

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

ROOT = b"mothra-news25"
BASE = path((ROOT,))
CATEGORY = path((ROOT, b"siblings"))
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
# The first and last child numbers that a boundary append may write.
FIRST_CHILD = 1
LAST_CHILD = 102
# A range whose last number minus its first reaches this span is refused.
SPAN_LIMIT = 10
# The observed reads are numbered from this identifier.
OBSERVE_ID_BASE = 1000
PAUSE_SECONDS = 3
QUIET_TIMEOUT_SECONDS = 3
APPEND_RANGE_MESSAGE = "Child append must be a bounded range within 1..102"


def post(identifier: int, number: int) -> list[Action]:
    """Plan a post to the shared category: the parent, or a numbered child.

    Returns
    -------
    list[native_plan.Action]
        The request and the read of its reply.
    """
    title = b"parent" if number == 0 else f"child-{number:03}".encode()
    return exchange(
        TYPE_POST_NEWS_ARTICLE,
        identifier,
        [
            (FIELD_NEWS_PATH, CATEGORY),
            (FIELD_ARTICLE_ID, (0 if number == 0 else 1).to_bytes(4, "big")),
            (FIELD_TITLE, title),
            (FIELD_FLAVOUR, b"text/plain"),
            (FIELD_BODY, b"body-" + title),
        ],
    )


def preflight() -> Case:
    """Plan the boundary preflight: the category listing and a file listing.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the preflight case.
    """
    steps = (
        login()
        + exchange(TYPE_LIST_NEWS_CATEGORIES, 10, [])
        + exchange(TYPE_LIST_FILES, 11, [(FIELD_FILE_PATH, b"\0\0")])
    )
    return [*steps, close()], {"kind": "news-boundary-preflight"}


def seed() -> Case:
    """Plan the boundary seed: the root folder, the category and the parent post.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the seed case.
    """
    steps = login() + exchange(TYPE_CREATE_NEWS_FOLDER, 10, [(FIELD_FILE_NAME, ROOT)])
    steps += exchange(
        TYPE_CREATE_NEWS_CATEGORY,
        11,
        [(FIELD_NEWS_NAME, b"siblings"), (FIELD_NEWS_PATH, BASE)],
    )
    steps += post(12, 0)
    steps += exchange(TYPE_LIST_NEWS_ARTICLES, 20, [(FIELD_NEWS_PATH, CATEGORY)])
    return [*steps, {"op": "pause", "seconds": PAUSE_SECONDS}, close()], {
        "kind": "news-boundary-seed"
    }


def append(first: int, last: int) -> Case:
    """Plan the paced posting of the children numbered ``first`` to ``last``.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the append case.

    Raises
    ------
    ValueError
        If the range is not within the bounds, or spans ``SPAN_LIMIT`` or more.
    """
    if not FIRST_CHILD <= first <= last <= LAST_CHILD or last - first >= SPAN_LIMIT:
        raise ValueError(APPEND_RANGE_MESSAGE)
    steps = login() + exchange(
        TYPE_LIST_NEWS_ARTICLES, 10, [(FIELD_NEWS_PATH, CATEGORY)]
    )
    for number in range(first, last + 1):
        steps += post(100 + number, number)
    steps += exchange(TYPE_LIST_NEWS_ARTICLES, 20, [(FIELD_NEWS_PATH, CATEGORY)])
    steps += exchange(TYPE_LIST_NEWS_ARTICLES, 21, [(FIELD_NEWS_PATH, CATEGORY)])
    return [*steps, {"op": "pause", "seconds": PAUSE_SECONDS}, close()], {
        "kind": "news-boundary-append",
        "first": first,
        "last": last,
    }


def observe() -> Case:
    """Plan the observation of the boundary children by their numbers.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the observation case.
    """
    steps = login() + exchange(
        TYPE_LIST_NEWS_ARTICLES, 10, [(FIELD_NEWS_PATH, CATEGORY)]
    )
    for identifier in [1, 2, 100, 101, 102, 103]:
        steps += exchange(
            TYPE_READ_NEWS_ARTICLE,
            OBSERVE_ID_BASE + identifier,
            [
                (FIELD_NEWS_PATH, CATEGORY),
                (FIELD_ARTICLE_ID, identifier.to_bytes(4, "big")),
                (FIELD_FLAVOUR, b"text/plain"),
            ],
        )
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 20, [(FIELD_NEWS_PATH, BASE)])
    steps += exchange(TYPE_EMPTY_ACK, 90, [])
    return [
        *steps,
        {"op": "expect_quiet", "connection": "main", "timeout": QUIET_TIMEOUT_SECONDS},
        close(),
    ], {"kind": "news-boundary-observe"}


def finalization() -> Case:
    """Plan the final listing after the upload that flushes the volume.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the final case.
    """
    steps = login() + upload(80, b"m-nb25-flush", b"\0\0")
    steps += exchange(TYPE_LIST_NEWS_ARTICLES, 10, [(FIELD_NEWS_PATH, CATEGORY)])
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 20, [(FIELD_NEWS_PATH, BASE)])
    return [*steps, close()], {"kind": "news-boundary-final"}


def cleanup() -> Case:
    """Plan the removal of the flushed upload and the final file listing.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the cleanup case.
    """
    steps = login() + exchange(TYPE_DELETE_NEWS_ITEM, 10, [(FIELD_NEWS_PATH, BASE)])
    steps += exchange(TYPE_DELETE_FILE, 11, [(FIELD_FILE_NAME, b"m-nb25-flush")])
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 90, [])
    steps += exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "news-boundary-cleanup"}


def publish_cleanup() -> Case:
    """Plan the upload that is published, and the file listings that follow it.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the publish case.
    """
    steps = login() + upload(80, b"m-nb25-publish", b"\0\0")
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 90, [])
    steps += exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "news-boundary-publish"}


def remove_publisher() -> Case:
    """Plan the removal of the published upload, and the listings that follow it.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the label of the remove case.
    """
    steps = login() + exchange(
        TYPE_DELETE_FILE, 10, [(FIELD_FILE_NAME, b"m-nb25-publish")]
    )
    steps += exchange(TYPE_LIST_NEWS_CATEGORIES, 90, [])
    steps += exchange(TYPE_LIST_FILES, 91, [(FIELD_FILE_PATH, b"\0\0")])
    return [*steps, close()], {"kind": "news-boundary-remove"}
