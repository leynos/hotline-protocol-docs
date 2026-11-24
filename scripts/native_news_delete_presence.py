"""Plan deletion field contrasts for two independently observed native trees."""

from native_folder_cases import path
from native_news_delete_cases import Cases, deletion_steps
from native_news_delete_specs import ROOT
from native_news_steps import (
    FIELD_ARTICLE_ID,
    FIELD_FLAGS,
    FIELD_NEWS_PATH,
    FIELD_RECURSIVE,
)


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
