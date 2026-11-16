"""Check the article-body and structure-change replies of the news corpus."""

from native_news_decode import categories
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_news_data import (
    FIELD_BODY,
    FIELD_CHILD,
    FIELD_DATE,
    FIELD_FLAVOUR,
    FIELD_FOLLOWING,
    FIELD_PARENT,
    FIELD_POSTER,
    FIELD_PREVIOUS,
    FIELD_TITLE,
    GRAPH,
    LIVENESS_ID,
    RECORDS,
)
from verify_native_shx import fields

BODY_READ_ID = 10  # the request that reads one article body
BODY_ERROR_CASES = frozenset({
    "no-flavour",
    "unknown-flavour",
    "flavour-case",
    "unknown-article",
})
BODY_ERROR_TEXT = b"Cannot get article data because an invalid category was specified."
STRUCTURE_BEFORE_ID = 10  # the category listing taken before a structure change
STRUCTURE_CHANGE_ID = 11  # the structure change, whose reply carries the error
STRUCTURE_AFTER_ID = 12  # the category listing taken after the rejected change
ACCESS_BITMAP_BYTES = 8  # the access bitmap is eight bytes


def body_reply(report: dict, expected: dict, by_id: dict) -> None:
    """Check the reply that reads one article body, or its error family."""
    frame = reply(report, BODY_READ_ID)
    identifier = expected["id"]
    if expected["case"] in BODY_ERROR_CASES:
        require(
            frame["error"] == 1
            and fields(frame) == {FIELD_ERROR_TEXT: BODY_ERROR_TEXT},
            "Body error family differs",
        )
    else:
        check_body_frame(frame, identifier, by_id)
    require(
        reply(report, LIVENESS_ID)["error"] == 0
        and fields(reply(report, LIVENESS_ID)) == {},
        "Body error/success lost control liveness",
    )


def check_body_frame(frame: dict, identifier: int, by_id: dict) -> None:
    """Check the body, title, navigation and date fields of an article read."""
    title, _, _, body = RECORDS[identifier]
    value = fields(frame)
    previous, following, parent, child = GRAPH[identifier]
    expected_fields = {
        FIELD_BODY: body,
        FIELD_TITLE: title,
        FIELD_POSTER: b"framing-fixture",
        FIELD_FLAVOUR: b"text/plain",
        FIELD_DATE: by_id[identifier]["date"],
        **{
            k: n.to_bytes(2, "big")
            for k, n in zip(
                [FIELD_PREVIOUS, FIELD_FOLLOWING, FIELD_PARENT, FIELD_CHILD],
                [previous, following, parent, child],
                strict=False,
            )
        },
    }
    require(
        frame["error"] == 0 and value == expected_fields,
        "Body bytes/navigation/date graph differs",
    )


def structure(report: dict, expected: dict) -> None:
    """Check the reply to one structure change and the listing around it."""
    label = expected["case"]
    if "low-" in label or label.endswith("low-permission"):
        operation = "delete" if label.startswith("delete") else "create"
        noun = "bundles" if "folder" in label else "categories"
        message = f"You are not allowed to {operation} news {noun}.".encode()
    elif label.startswith("delete"):
        message = b"Cannot delete news item because it could not be found."
    else:
        noun = b"bundle" if label.startswith("folder") else b"category"
        name = (
            b"bundle"
            if label.endswith("conflict-folder")
            else b"category"
            if label.endswith("conflict-category")
            else b"new"
        )
        reason = (
            b"there is already an item or bundle with that name."
            if "conflict" in label
            else b"the enclosing bundle could not be found."
        )
        message = (
            b"Cannot create news " + noun + b" \xd2" + name + b"\xd3 because " + reason
        )
    require(
        reply(report, STRUCTURE_CHANGE_ID)["error"] == 1
        and fields(reply(report, STRUCTURE_CHANGE_ID)) == {FIELD_ERROR_TEXT: message},
        "Structure error outcome differs",
    )
    before = categories(reply(report, STRUCTURE_BEFORE_ID))
    after = categories(reply(report, STRUCTURE_AFTER_ID))
    require(
        [{k: v for k, v in r.items() if k != "tail"} for r in before]
        == [{k: v for k, v in r.items() if k != "tail"} for r in after],
        "Rejected structure operation changed semantic listing",
    )
    access = next(
        f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access)
        == {
            FIELD_ACCESS_BITMAP: bytes(ACCESS_BITMAP_BYTES)
            if expected["role"] == "low"
            else ADMIN
        },
        "Structure privilege control differs",
    )
    require(
        reply(report, LIVENESS_ID)["error"] == 0,
        "Structure failure lost control liveness",
    )
