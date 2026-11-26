"""Prepare owned news hierarchy and category-list version observations."""

from native_auth_cases import authentication
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login, packet, payload, send

ROOT = b"mothra-news23"
BASE = path((ROOT,))
VERSIONS = [0, 1, 14, 15, 16, 149, 150, 190, 65535]


def preflight() -> dict:
    """Build the plan that checks the news tree before the capture."""
    steps = login() + exchange(370, 10, []) + exchange(500, 90, []) + [close()]
    return {"preflight": (steps, {"kind": "news-preflight"})}


def files_preflight() -> dict:
    """Build the plan that checks the file tree before the capture."""
    steps = login() + exchange(200, 10, [(202, b"\0\0")]) + [close()]
    return {"files": (steps, {"kind": "news-files-preflight"})}


def seed() -> dict:
    """Build the plan that creates the news folders and categories."""
    steps = login() + exchange(381, 10, [(201, ROOT)])
    for identifier, name in [(20, b"bundle"), (21, b"empty"), (22, b"hi-\x9a")]:
        steps += exchange(381, identifier, [(201, name), (325, BASE)])
    for identifier, name, parent in [
        (30, b"category", BASE),
        (31, b"zero-articles", BASE),
        (32, b"nested", path((ROOT, b"bundle"))),
        (33, b"deep", path((ROOT, b"bundle", b"child"))),
    ]:
        if identifier == 33:
            steps += exchange(
                381, 32, [(201, b"child"), (325, path((ROOT, b"bundle")))]
            )
        steps += exchange(382, identifier, [(322, name), (325, parent)])
    steps += exchange(370, 90, [(325, BASE)]) + [close()]
    return {"seed": (steps, {"kind": "news-seed"})}


def listings() -> dict:
    """Build one plan per client version that lists the news folders and categories."""
    result = {}
    for version in VERSIONS:
        steps = login()
        steps[3] = send(
            packet(
                107,
                1,
                payload(
                    [
                        (105, bytes(b ^ 255 for b in b"admin")),
                        (106, bytes(b ^ 255 for b in b"mothra19")),
                        (160, version.to_bytes(2, "big")),
                        (102, b"news-fixture"),
                        (104, b"\0\1"),
                    ]
                ),
            )
        )
        for identifier, parent in [
            (10, BASE),
            (11, path((ROOT, b"empty"))),
            (12, path((ROOT, b"bundle"))),
            (13, path((ROOT, b"bundle", b"child"))),
        ]:
            steps += exchange(370, identifier, [(325, parent)])
        steps += exchange(371, 20, [(325, path((ROOT, b"category")))])
        steps += exchange(371, 21, [(325, path((ROOT, b"zero-articles")))])
        steps += exchange(371, 22, [(325, path((ROOT, b"bundle", b"nested")))])
        steps += exchange(500, 90, []) + [
            {"op": "expect_quiet", "connection": "main", "timeout": 1},
            close(),
        ]
        result[f"version-{version}"] = (
            steps,
            {"kind": "news-listing", "version": version},
        )
    return result


def posts() -> dict:
    """Build the plan that posts the root articles, including one without a body."""
    steps = login() + exchange(370, 10, [(325, BASE)])
    steps += exchange(371, 11, [(325, path((ROOT, b"category")))])
    for identifier, category, title, flags, content in [
        (20, (ROOT, b"category"), b"First root", 0, b"first-body\r\n\0\xff"),
        (21, (ROOT, b"category"), b"Second root", 0x11223344, b"second-body"),
        (22, (ROOT, b"bundle", b"nested"), b"Nested root", 0, b"nested-body"),
        (23, (ROOT, b"category"), b"Missing body", 0, None),
    ]:
        values = [
            (325, path(category)),
            (328, title),
            (334, flags.to_bytes(4, "big")),
            (327, b"text/plain"),
        ]
        if content is not None:
            values.append((333, content))
        steps += exchange(410, identifier, values)
        steps += exchange(370, identifier + 10, [(325, BASE)])
        steps += exchange(371, identifier + 20, [(325, path(category))])
    steps += exchange(500, 90, []) + [
        {"op": "expect_quiet", "connection": "main", "timeout": 1},
        close(),
    ]
    return {
        "posts": (
            steps,
            {
                "kind": "news-posts",
                "scope": "Three valid root posts and one missing-body request; inspect effects independently of ACK status.",
            },
        )
    }


def thread_children(parent: int) -> dict:
    """Build the plan that posts child articles under a parent article."""
    steps = login()
    for identifier, title, content in [
        (20, b"long-" + b"x" * 59, b"B" * 65535),
        (21, b"Second child", b"child-two"),
    ]:
        steps += exchange(
            410,
            identifier,
            [
                (325, path((ROOT, b"category"))),
                (326, parent.to_bytes(4, "big")),
                (328, title),
                (327, b"text/plain"),
                (333, content),
            ],
        )
        steps += exchange(371, identifier + 20, [(325, path((ROOT, b"category")))])
    steps += exchange(500, 90, []) + [close()]
    return {"children": (steps, {"kind": "news-thread-children", "parent": parent})}


def thread_grandchild(parent: int) -> dict:
    """Build the plan that posts a grandchild article and lists the category."""
    steps = login() + exchange(
        410,
        20,
        [
            (325, path((ROOT, b"category"))),
            (326, parent.to_bytes(4, "big")),
            (328, b"Grandchild"),
            (327, b"text/plain"),
            (333, b"grandchild-body"),
        ],
    )
    steps += (
        exchange(371, 40, [(325, path((ROOT, b"category")))])
        + exchange(500, 90, [])
        + [close()]
    )
    return {"grandchild": (steps, {"kind": "news-thread-grandchild", "parent": parent})}


def structures() -> dict:
    """Build one plan per case: conflicting or parentless folder and category creation, deletions and low-permission creation."""
    result = {}
    for label, kind, values, role in [
        ("folder-conflict-folder", 381, [(201, b"bundle"), (325, BASE)], "admin"),
        ("folder-conflict-category", 381, [(201, b"category"), (325, BASE)], "admin"),
        ("category-conflict-folder", 382, [(322, b"bundle"), (325, BASE)], "admin"),
        ("category-conflict-category", 382, [(322, b"category"), (325, BASE)], "admin"),
        (
            "folder-missing-parent",
            381,
            [(201, b"new"), (325, path((ROOT, b"missing")))],
            "admin",
        ),
        (
            "category-missing-parent",
            382,
            [(322, b"new"), (325, path((ROOT, b"missing")))],
            "admin",
        ),
        (
            "folder-category-parent",
            381,
            [(201, b"new"), (325, path((ROOT, b"category")))],
            "admin",
        ),
        (
            "category-category-parent",
            382,
            [(322, b"new"), (325, path((ROOT, b"category")))],
            "admin",
        ),
        ("folder-low-permission", 381, [(201, b"new"), (325, BASE)], "low"),
        ("category-low-permission", 382, [(322, b"new"), (325, BASE)], "low"),
        ("delete-low-folder", 380, [(325, path((ROOT, b"bundle")))], "low"),
        ("delete-low-category", 380, [(325, path((ROOT, b"category")))], "low"),
        ("delete-missing", 380, [(325, path((ROOT, b"missing")))], "admin"),
        ("delete-protected-news-root", 380, [], "admin"),
    ]:
        steps = login()
        if role == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        steps += exchange(370, 10, [(325, BASE)]) + exchange(kind, 11, values)
        steps += exchange(370, 12, [(325, BASE)]) + exchange(500, 90, [])
        steps += [{"op": "expect_quiet", "connection": "main", "timeout": 1}, close()]
        result[label] = (
            steps,
            {"kind": "news-structure", "case": label, "request": kind, "role": role},
        )
    return result


def finalization() -> dict:
    """Build the plan that flushes the volume and reads back the news tree."""
    steps = login() + exchange(370, 10, [(325, BASE)])
    # File upload supplies the previously verified native volume-flush path.
    steps += upload(80, b"m-news23-flush", b"\0\0")
    steps += exchange(370, 90, []) + [close()]
    return {"final": (steps, {"kind": "news-final"})}


def cleanup() -> dict:
    """Build the plan that deletes the news tree and the flush file."""
    steps = login() + exchange(380, 10, [(325, BASE)])
    steps += exchange(204, 11, [(201, b"m-news23-flush")])
    steps += exchange(370, 90, []) + exchange(500, 91, []) + [close()]
    return {"cleanup": (steps, {"kind": "news-cleanup"})}


def publish_cleanup() -> dict:
    """Build the plan that publishes the news changes with a flush file."""
    steps = login() + exchange(200, 10, [(202, b"\0\0")])
    steps += upload(80, b"m-news23-publish", b"\0\0")
    steps += exchange(370, 90, []) + exchange(200, 91, [(202, b"\0\0")]) + [close()]
    return {"publish": (steps, {"kind": "news-publish-cleanup"})}


def remove_publisher() -> dict:
    """Build the plan that removes the publishing flush file."""
    steps = login() + exchange(204, 10, [(201, b"m-news23-publish")])
    steps += (
        exchange(200, 90, [(202, b"\0\0")])
        + exchange(370, 91, [])
        + exchange(500, 92, [])
        + [close()]
    )
    return {"remove": (steps, {"kind": "news-remove-publisher"})}


def bodies() -> dict:
    """Build one plan per case that requests an article body in a given flavour."""
    result = {}
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
        steps = login() + exchange(
            400,
            10,
            [
                (325, path((ROOT, b"category"))),
                (326, identifier.to_bytes(4, "big")),
                (327, flavour),
            ],
        )
        steps += exchange(500, 90, []) + [
            {"op": "expect_quiet", "connection": "main", "timeout": 1},
            close(),
        ]
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
