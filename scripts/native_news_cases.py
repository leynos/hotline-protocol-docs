"""Prepare owned news hierarchy and category-list version observations."""

import typing as typ

from native_folder_cases import path
from native_mkdir_cases import exchange
from native_news_steps import (
    BASE,
    FIELD_ARTICLE_ID,
    FIELD_BODY,
    FIELD_FLAGS,
    FIELD_FLAVOUR,
    FIELD_NEWS_NAME,
    FIELD_NEWS_PATH,
    FIELD_TITLE,
    LOGIN_REQUEST_STEP,
    ROOT,
    TYPE_CREATE_NEWS_CATEGORY,
    TYPE_CREATE_NEWS_FOLDER,
    TYPE_LIST_NEWS_ARTICLES,
    TYPE_LIST_NEWS_CATEGORIES,
    TYPE_POST_NEWS_ARTICLE,
    bodies,
    cleanup,
    finalization,
    publish_cleanup,
    remove_publisher,
    structures,
)
from native_plan import COMPLEMENT_MASK, Action, close, login, packet, payload, send
from native_wire_names import (
    FIELD_FILE_NAME,
    FIELD_FILE_PATH,
    FIELD_ICON,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_VERSION,
    TYPE_EMPTY_ACK,
    TYPE_LIST_FILES,
    TYPE_LOGIN,
)

# The structure, body and cleanup cases, and the shared names, come from
# native_news_steps.
# verify_native_news imports ROOT, VERSIONS, bodies, cleanup, files_preflight,
# finalization, listings, posts, preflight, publish_cleanup, remove_publisher, seed,
# structures, thread_children and thread_grandchild; prepare_native_cases imports
# the same planners by name, and the news verifiers reach ROOT through this module.
__all__ = [
    "BASE",
    "ROOT",
    "VERSIONS",
    "bodies",
    "cleanup",
    "files_preflight",
    "finalization",
    "listings",
    "posts",
    "preflight",
    "publish_cleanup",
    "remove_publisher",
    "seed",
    "structures",
    "thread_children",
    "thread_grandchild",
]

type Case = tuple[list[Action], dict[str, typ.Any]]
type Cases = dict[str, Case]

VERSIONS = [0, 1, 14, 15, 16, 149, 150, 190, 65535]
# The numbered category that the seed nests one level deeper.
DEEP_CATEGORY_ID = 33
# The title is "long-" followed by this many bytes, and the body fills a field.
LONG_TITLE_FILL = 59
FULL_FIELD_BYTES = 65535


def preflight() -> Cases:
    """Plan the news preflight: the category listing and an acknowledgement.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one preflight case, by its label.
    """
    steps = (
        login()
        + exchange(TYPE_LIST_NEWS_CATEGORIES, 10, [])
        + exchange(TYPE_EMPTY_ACK, 90, [])
        + [close()]
    )
    return {"preflight": (steps, {"kind": "news-preflight"})}


def files_preflight() -> Cases:
    """Plan the file-listing preflight of the news root.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one file preflight case, by its label.
    """
    steps = (
        login()
        + exchange(TYPE_LIST_FILES, 10, [(FIELD_FILE_PATH, b"\0\0")])
        + [close()]
    )
    return {"files": (steps, {"kind": "news-files-preflight"})}


def seed() -> Cases:
    """Plan the seeding of the news folders, categories and the parent post.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one seed case, by its label.
    """
    steps = login() + exchange(TYPE_CREATE_NEWS_FOLDER, 10, [(FIELD_FILE_NAME, ROOT)])
    for identifier, name in [(20, b"bundle"), (21, b"empty"), (22, b"hi-\x9a")]:
        steps += exchange(
            TYPE_CREATE_NEWS_FOLDER,
            identifier,
            [(FIELD_FILE_NAME, name), (FIELD_NEWS_PATH, BASE)],
        )
    for identifier, name, parent in [
        (30, b"category", BASE),
        (31, b"zero-articles", BASE),
        (32, b"nested", path((ROOT, b"bundle"))),
        (33, b"deep", path((ROOT, b"bundle", b"child"))),
    ]:
        if identifier == DEEP_CATEGORY_ID:
            steps += exchange(
                TYPE_CREATE_NEWS_FOLDER,
                32,
                [
                    (FIELD_FILE_NAME, b"child"),
                    (FIELD_NEWS_PATH, path((ROOT, b"bundle"))),
                ],
            )
        steps += exchange(
            TYPE_CREATE_NEWS_CATEGORY,
            identifier,
            [(FIELD_NEWS_NAME, name), (FIELD_NEWS_PATH, parent)],
        )
    steps += [
        *exchange(TYPE_LIST_NEWS_CATEGORIES, 90, [(FIELD_NEWS_PATH, BASE)]),
        close(),
    ]
    return {"seed": (steps, {"kind": "news-seed"})}


def listings() -> Cases:
    """Plan one category and article listing for each controlled client version.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        One listing case per version in ``VERSIONS``, keyed by its version.
    """
    result: Cases = {}
    for version in VERSIONS:
        steps = login()
        steps[LOGIN_REQUEST_STEP] = send(
            packet(
                TYPE_LOGIN,
                1,
                payload([
                    (FIELD_LOGIN, bytes(b ^ COMPLEMENT_MASK for b in b"admin")),
                    (
                        FIELD_PASSWORD,
                        bytes(b ^ COMPLEMENT_MASK for b in b"mothra19"),
                    ),
                    (FIELD_VERSION, version.to_bytes(2, "big")),
                    (FIELD_NAME, b"news-fixture"),
                    (FIELD_ICON, b"\0\1"),
                ]),
            )
        )
        for identifier, parent in [
            (10, BASE),
            (11, path((ROOT, b"empty"))),
            (12, path((ROOT, b"bundle"))),
            (13, path((ROOT, b"bundle", b"child"))),
        ]:
            steps += exchange(
                TYPE_LIST_NEWS_CATEGORIES, identifier, [(FIELD_NEWS_PATH, parent)]
            )
        steps += exchange(
            TYPE_LIST_NEWS_ARTICLES,
            20,
            [(FIELD_NEWS_PATH, path((ROOT, b"category")))],
        )
        steps += exchange(
            TYPE_LIST_NEWS_ARTICLES,
            21,
            [(FIELD_NEWS_PATH, path((ROOT, b"zero-articles")))],
        )
        steps += exchange(
            TYPE_LIST_NEWS_ARTICLES,
            22,
            [(FIELD_NEWS_PATH, path((ROOT, b"bundle", b"nested")))],
        )
        steps += [
            *exchange(TYPE_EMPTY_ACK, 90, []),
            {"op": "expect_quiet", "connection": "main", "timeout": 1},
            close(),
        ]
        result[f"version-{version}"] = (
            steps,
            {"kind": "news-listing", "version": version},
        )
    return result


def posts() -> Cases:
    """Plan three valid root posts and one post whose body is missing.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one posting case, by its label.
    """
    steps = login() + exchange(TYPE_LIST_NEWS_CATEGORIES, 10, [(FIELD_NEWS_PATH, BASE)])
    steps += exchange(
        TYPE_LIST_NEWS_ARTICLES, 11, [(FIELD_NEWS_PATH, path((ROOT, b"category")))]
    )
    for identifier, category, title, flags, content in [
        (20, (ROOT, b"category"), b"First root", 0, b"first-body\r\n\0\xff"),
        (21, (ROOT, b"category"), b"Second root", 0x11223344, b"second-body"),
        (22, (ROOT, b"bundle", b"nested"), b"Nested root", 0, b"nested-body"),
        (23, (ROOT, b"category"), b"Missing body", 0, None),
    ]:
        values = [
            (FIELD_NEWS_PATH, path(category)),
            (FIELD_TITLE, title),
            (FIELD_FLAGS, flags.to_bytes(4, "big")),
            (FIELD_FLAVOUR, b"text/plain"),
        ]
        if content is not None:
            values.append((FIELD_BODY, content))
        steps += exchange(TYPE_POST_NEWS_ARTICLE, identifier, values)
        steps += exchange(
            TYPE_LIST_NEWS_CATEGORIES, identifier + 10, [(FIELD_NEWS_PATH, BASE)]
        )
        steps += exchange(
            TYPE_LIST_NEWS_ARTICLES,
            identifier + 20,
            [(FIELD_NEWS_PATH, path(category))],
        )
    steps += [
        *exchange(TYPE_EMPTY_ACK, 90, []),
        {"op": "expect_quiet", "connection": "main", "timeout": 1},
        close(),
    ]
    return {
        "posts": (
            steps,
            {
                "kind": "news-posts",
                "scope": (
                    "Three valid root posts and one missing-body request; "
                    "inspect effects independently of ACK status."
                ),
            },
        )
    }


def thread_children(parent: int) -> Cases:
    """Plan two replies to the article numbered ``parent``, and their listings.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one thread case, by its label.
    """
    steps = login()
    for identifier, title, content in [
        (20, b"long-" + b"x" * LONG_TITLE_FILL, b"B" * FULL_FIELD_BYTES),
        (21, b"Second child", b"child-two"),
    ]:
        steps += exchange(
            TYPE_POST_NEWS_ARTICLE,
            identifier,
            [
                (FIELD_NEWS_PATH, path((ROOT, b"category"))),
                (FIELD_ARTICLE_ID, parent.to_bytes(4, "big")),
                (FIELD_TITLE, title),
                (FIELD_FLAVOUR, b"text/plain"),
                (FIELD_BODY, content),
            ],
        )
        steps += exchange(
            TYPE_LIST_NEWS_ARTICLES,
            identifier + 20,
            [(FIELD_NEWS_PATH, path((ROOT, b"category")))],
        )
    steps += [*exchange(TYPE_EMPTY_ACK, 90, []), close()]
    return {"children": (steps, {"kind": "news-thread-children", "parent": parent})}


def thread_grandchild(parent: int) -> Cases:
    """Plan one reply to the article numbered ``parent``, and its listing.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The one thread case, by its label.
    """
    steps = login() + exchange(
        TYPE_POST_NEWS_ARTICLE,
        20,
        [
            (FIELD_NEWS_PATH, path((ROOT, b"category"))),
            (FIELD_ARTICLE_ID, parent.to_bytes(4, "big")),
            (FIELD_TITLE, b"Grandchild"),
            (FIELD_FLAVOUR, b"text/plain"),
            (FIELD_BODY, b"grandchild-body"),
        ],
    )
    steps += (
        exchange(
            TYPE_LIST_NEWS_ARTICLES,
            40,
            [(FIELD_NEWS_PATH, path((ROOT, b"category")))],
        )
        + exchange(TYPE_EMPTY_ACK, 90, [])
        + [close()]
    )
    return {"grandchild": (steps, {"kind": "news-thread-grandchild", "parent": parent})}
