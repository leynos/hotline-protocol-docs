"""Plan deletion field contrasts for two independently observed native trees."""

from native_folder_cases import path
from native_metadata_cases import upload
from native_mkdir_cases import exchange
from native_news_delete_cases import (
    TYPE_370,
    TYPE_371,
    Cases,
    cleanup,
    deletion_steps,
    preflight,
    publish_cleanup,
    remove_publisher,
    resume_category,
    seed,
)
from native_news_delete_specs import BASE, ROOT
from native_news_steps import (
    FIELD_ARTICLE_ID,
    FIELD_FLAGS,
    FIELD_NEWS_PATH,
    FIELD_RECURSIVE,
)
from native_plan import close, login
from native_wire_names import TYPE_EMPTY_ACK


def delete_presence() -> Cases:
    """Plan the three encodings of the article identifier and flags.

    Returns
    -------
    Cases
        One separately capturable session per field and encoding. Each flags
        session requires a fresh copy of the complete eight-article tree.
    """
    result: Cases = {}
    for field, name, recursive in (
        (FIELD_ARTICLE_ID, b"missing-id-field", b"\x01"),
        (FIELD_FLAGS, b"parent-four-zero", bytes(4)),
    ):
        category = path((ROOT, name))
        for shape, value in (("absent", None), ("empty", b""), ("zero", bytes(4))):
            values = [(FIELD_NEWS_PATH, category)]
            if field == FIELD_FLAGS:
                values.append((FIELD_ARTICLE_ID, (2).to_bytes(4, "big")))
            if value is not None:
                values.append((field, value))
            values.append((FIELD_RECURSIVE, recursive))
            result[f"{field}-{shape}"] = (
                deletion_steps(category, values, "admin", repeat=False),
                {"kind": "news-delete-presence", "field": field, "encoding": shape},
            )
    return result


def delete_presence_setup() -> Cases:
    """Prepare, inspect and remove the two owned presence-control categories.

    Returns
    -------
    Cases
        Separate plans for the preflight, root, two paced seeds, final
        publication of the current lists, cleanup and publisher retirement.
    """
    cases = {
        **preflight(),
        **seed(),
        **cleanup(),
        **publish_cleanup(),
        **remove_publisher(),
    }
    steps = [*login(), *upload(80, b"m-nd24-flush", bytes(2))]
    for identifier, name in enumerate(("missing-id-field", "parent-four-zero"), 100):
        cases[f"seed-{name}"] = resume_category(name)[name]
        steps += exchange(
            TYPE_371, identifier, [(FIELD_NEWS_PATH, path((ROOT, name.encode())))]
        )
    steps += [
        *exchange(TYPE_370, 900, [(FIELD_NEWS_PATH, BASE)]),
        *exchange(TYPE_EMPTY_ACK, 90, []),
        close(),
    ]
    cases["flush"] = (steps, {"kind": "news-delete-presence-flush"})
    return cases
