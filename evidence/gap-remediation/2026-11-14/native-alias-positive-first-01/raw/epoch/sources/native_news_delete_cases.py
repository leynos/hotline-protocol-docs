"""Prepare isolated article-deletion trees, scalar controls and native cleanup."""

from native_auth_cases import authentication
from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_plan import close, login

ROOT = b"mothra-news24"
BASE = path((ROOT,))
NODES = [
    (1, b"L", 0),
    (2, b"A", 0),
    (3, b"R", 0),
    (4, b"B", 2),
    (5, b"C", 2),
    (6, b"F", 2),
    (7, b"D", 4),
    (8, b"E", 4),
]


def specs() -> list[dict]:
    """Return the article deletion cases, each with its case name, mode and optional hexadecimal value."""
    result = []
    for label, value, recursive in [
        ("absent", None, False),
        ("empty", b"", False),
        ("one-zero", b"\0", False),
        ("two-zero", bytes(2), False),
        ("four-zero", bytes(4), False),
        ("one-one", b"\1", True),
        ("one-two", b"\2", True),
        ("one-ff", b"\xff", True),
        ("two-one", b"\0\1", True),
        ("two-high", b"\x80\0", True),
        ("four-high", b"\0\1\0\0", True),
        ("three-one", b"\0\0\1", False),
        ("five-one", b"\0\0\0\1\xff", True),
        ("five-zero", b"\0\0\0\0\xff", False),
    ]:
        result.append(
            {
                "case": "parent-" + label,
                "article": 2,
                "value_hex": None if value is None else value.hex(),
                "mode": "recursive-parent" if recursive else "promote-parent",
                "role": "admin",
                "missing_category": False,
                "repeat": False,
            }
        )
    for label, article, value, mode, role, missing, repeat in [
        ("leaf-zero", 7, b"\0", "leaf", "admin", False, False),
        ("leaf-one", 7, b"\1", "leaf", "admin", False, False),
        ("middle-zero", 4, b"\0", "promote-middle", "admin", False, False),
        ("middle-one", 4, b"\1", "recursive-middle", "admin", False, False),
        ("root-head", 1, b"\0", "head", "admin", False, False),
        ("root-tail", 3, b"\0", "tail", "admin", False, False),
        ("missing-id", 99, b"\1", "unchanged", "admin", False, False),
        ("denied", 2, b"\1", "unchanged", "low", False, False),
        ("missing-category", 2, b"\1", "unchanged", "admin", True, False),
        ("missing-id-field", None, b"\1", "unchanged", "admin", False, False),
        ("repeat-delete", 2, b"\0", "promote-parent", "admin", False, True),
    ]:
        result.append(
            {
                "case": label,
                "article": article,
                "value_hex": value.hex(),
                "mode": mode,
                "role": role,
                "missing_category": missing,
                "repeat": repeat,
            }
        )
    return result


def preflight() -> dict:
    """Build the plan that looks up the fixture state before the capture."""
    steps = login() + exchange(370, 10, []) + exchange(200, 11, [(202, b"\0\0")])
    steps += exchange(352, 12, [(105, b"fixture-low")]) + [close()]
    return {"preflight": (steps, {"kind": "news-delete-preflight"})}


def initial_burst_seed() -> dict:
    """Reconstruct the retained unpaced failed plan; never exposed by the CLI."""
    steps = login() + exchange(381, 10, [(201, ROOT)])
    counter = 100
    for spec in specs():
        name = spec["case"].encode()
        category = path((ROOT, name))
        steps += exchange(382, counter, [(322, name), (325, BASE)])
        counter += 1
        for _, title, parent in NODES:
            steps += exchange(
                410,
                counter,
                [
                    (325, category),
                    (326, parent.to_bytes(4, "big")),
                    (328, title),
                    (327, b"text/plain"),
                    (333, b"body-" + title),
                ],
            )
            counter += 1
    steps += exchange(370, 900, [(325, BASE)]) + [close()]
    return {"seed": (steps, {"kind": "news-delete-seed"})}


def seed() -> dict:
    """Build the plan that creates the root news category."""
    steps = (
        login()
        + exchange(381, 10, [(201, ROOT)])
        + exchange(370, 90, [(325, BASE)])
        + [close()]
    )
    return {"root": (steps, {"kind": "news-delete-root"})}


def inspect_seed() -> dict:
    """Build the plan that lists the seeded categories."""
    steps = login() + exchange(370, 10, [(325, BASE)])
    for identifier, spec in enumerate(specs(), 100):
        steps += exchange(371, identifier, [(325, path((ROOT, spec["case"].encode())))])
    steps += exchange(500, 90, []) + [close()]
    return {"inventory": (steps, {"kind": "news-delete-inventory"})}


def resume_category(case: str, completed: int = 0, exists: bool = False) -> dict:
    """Build the plan that creates a case's category unless it exists and then posts the remaining articles; it rejects an invalid case or prefix."""
    if (
        case not in {s["case"] for s in specs()}
        or not 0 <= completed <= len(NODES)
        or (completed and not exists)
    ):
        raise ValueError("Invalid owned category/prefix")
    category = path((ROOT, case.encode()))
    steps = login()
    if exists:
        steps += exchange(371, 10, [(325, category)])
    else:
        steps += exchange(382, 11, [(322, case.encode()), (325, BASE)])
    for identifier, (_, title, parent) in enumerate(NODES[completed:], 100):
        steps += exchange(
            410,
            identifier,
            [
                (325, category),
                (326, parent.to_bytes(4, "big")),
                (328, title),
                (327, b"text/plain"),
                (333, b"body-" + title),
            ],
        )
    steps += exchange(371, 20, [(325, category)]) + [
        {"op": "pause", "seconds": 3},
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


def seed_categories() -> dict:
    """Build the plans that create every case's category and articles."""
    result = {}
    for spec in specs():
        result.update(resume_category(spec["case"]))
    return result


def deletions() -> dict:
    """Build one plan per case that attempts to delete an article, including the denied and missing cases, and reads the category back."""
    result = {}
    for spec in specs():
        category = path((ROOT, spec["case"].encode()))
        values = [
            (325, path((ROOT, b"missing")) if spec["missing_category"] else category)
        ]
        if spec["article"] is not None:
            values.append((326, spec["article"].to_bytes(4, "big")))
        if spec["value_hex"] is not None:
            values.append((337, bytes.fromhex(spec["value_hex"])))
        steps = login()
        if spec["role"] == "low":
            steps[3] = authentication(b"fixture-low", b"next-pass")
        steps += exchange(371, 10, [(325, category)])
        steps += exchange(411, 11, values)
        if spec["repeat"]:
            steps += exchange(411, 12, values)
        steps += exchange(371, 20, [(325, category)]) + exchange(
            371, 21, [(325, category)]
        )
        for identifier, _, _ in NODES if spec["role"] == "admin" else NODES[:1]:
            steps += exchange(
                400,
                100 + identifier,
                [
                    (325, category),
                    (326, identifier.to_bytes(4, "big")),
                    (327, b"text/plain"),
                ],
            )
        steps += exchange(500, 90, []) + [
            {"op": "expect_quiet", "connection": "main", "timeout": 3},
            close(),
        ]
        result[spec["case"]] = (steps, {"kind": "news-delete", **spec})
    return result


def finalization() -> dict:
    """Build the plan that flushes, lists every category and reads back the articles of the denied category."""
    steps = login() + upload(80, b"m-nd24-flush", b"\0\0")
    for identifier, spec in enumerate(specs(), 100):
        steps += exchange(371, identifier, [(325, path((ROOT, spec["case"].encode())))])
    for identifier, _, _ in NODES:
        steps += exchange(
            400,
            500 + identifier,
            [
                (325, path((ROOT, b"denied"))),
                (326, identifier.to_bytes(4, "big")),
                (327, b"text/plain"),
            ],
        )
    steps += exchange(370, 900, [(325, BASE)]) + [close()]
    return {"final": (steps, {"kind": "news-delete-final"})}


def cleanup() -> dict:
    """Build the plan that deletes the root category and moves the flush file to Trash."""
    steps = (
        login()
        + exchange(380, 10, [(325, BASE)])
        + exchange(204, 11, [(201, b"m-nd24-flush")])
    )
    steps += exchange(370, 90, []) + exchange(200, 91, [(202, b"\0\0")]) + [close()]
    return {"cleanup": (steps, {"kind": "news-delete-cleanup"})}


def publish_cleanup() -> dict:
    """Build the plan that publishes the news changes with a flush file."""
    steps = login() + upload(80, b"m-nd24-publish", b"\0\0")
    steps += exchange(370, 90, []) + exchange(200, 91, [(202, b"\0\0")]) + [close()]
    return {"publish": (steps, {"kind": "news-delete-publish"})}


def remove_publisher() -> dict:
    """Build the plan that removes the publishing flush file."""
    steps = login() + exchange(204, 10, [(201, b"m-nd24-publish")])
    steps += (
        exchange(370, 90, [])
        + exchange(200, 91, [(202, b"\0\0")])
        + exchange(500, 92, [])
        + [close()]
    )
    return {"remove": (steps, {"kind": "news-delete-remove-publisher"})}
