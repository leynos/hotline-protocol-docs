"""Prepare paced, owned child-append boundary observations."""

from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login

ROOT = b"mothra-news25"
BASE = path((ROOT,))
CATEGORY = path((ROOT, b"siblings"))


def post(identifier: int, number: int) -> list[dict]:
    """Return the steps that post the parent article or one numbered child article."""
    title = b"parent" if number == 0 else f"child-{number:03}".encode()
    return exchange(
        410,
        identifier,
        [
            (325, CATEGORY),
            (326, (0 if number == 0 else 1).to_bytes(4, "big")),
            (328, title),
            (327, b"text/plain"),
            (333, b"body-" + title),
        ],
    )


def preflight() -> tuple[list[dict], dict]:
    """Build the plan that checks the news and file trees before the capture."""
    steps = login() + exchange(370, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    return steps + [close()], {"kind": "news-boundary-preflight"}


def seed() -> tuple[list[dict], dict]:
    """Build the plan that creates the folder and category and posts the parent article."""
    steps = login() + exchange(381, 10, [(201, ROOT)])
    steps += exchange(382, 11, [(322, b"siblings"), (325, BASE)])
    steps += post(12, 0)
    steps += exchange(371, 20, [(325, CATEGORY)])
    return steps + [{"op": "pause", "seconds": 3}, close()], {
        "kind": "news-boundary-seed"
    }


def append(first: int, last: int) -> tuple[list[dict], dict]:
    """Build the plan that appends a bounded range of child articles and lists the category twice."""
    if not 1 <= first <= last <= 102 or last - first >= 10:
        raise ValueError("Child append must be a bounded range within 1..102")
    steps = login() + exchange(371, 10, [(325, CATEGORY)])
    for number in range(first, last + 1):
        steps += post(100 + number, number)
    steps += exchange(371, 20, [(325, CATEGORY)])
    steps += exchange(371, 21, [(325, CATEGORY)])
    return steps + [{"op": "pause", "seconds": 3}, close()], {
        "kind": "news-boundary-append",
        "first": first,
        "last": last,
    }


def observe() -> tuple[list[dict], dict]:
    """Build the plan that reads the first and last articles and lists the category."""
    steps = login() + exchange(371, 10, [(325, CATEGORY)])
    for identifier in [1, 2, 100, 101, 102, 103]:
        steps += exchange(
            400,
            1000 + identifier,
            [
                (325, CATEGORY),
                (326, identifier.to_bytes(4, "big")),
                (327, b"text/plain"),
            ],
        )
    steps += exchange(370, 20, [(325, BASE)])
    steps += exchange(500, 90, [])
    return steps + [
        {"op": "expect_quiet", "connection": "main", "timeout": 3},
        close(),
    ], {"kind": "news-boundary-observe"}


def finalization() -> tuple[list[dict], dict]:
    """Build the plan that flushes the volume and reads back the category."""
    steps = login() + upload(80, b"m-nb25-flush", b"\0\0")
    steps += exchange(371, 10, [(325, CATEGORY)])
    steps += exchange(370, 20, [(325, BASE)])
    return steps + [close()], {"kind": "news-boundary-final"}


def cleanup() -> tuple[list[dict], dict]:
    """Build the plan that deletes the news folder and the flush file."""
    steps = login() + exchange(380, 10, [(325, BASE)])
    steps += exchange(204, 11, [(201, b"m-nb25-flush")])
    steps += exchange(370, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "news-boundary-cleanup"}


def publish_cleanup() -> tuple[list[dict], dict]:
    """Build the plan that publishes the news changes with a flush file."""
    steps = login() + upload(80, b"m-nb25-publish", b"\0\0")
    steps += exchange(370, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "news-boundary-publish"}


def remove_publisher() -> tuple[list[dict], dict]:
    """Build the plan that removes the publishing flush file."""
    steps = login() + exchange(204, 10, [(201, b"m-nb25-publish")])
    steps += exchange(370, 90, []) + exchange(200, 91, [(202, b"\0\0")])
    return steps + [close()], {"kind": "news-boundary-remove"}
