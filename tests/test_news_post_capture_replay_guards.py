"""Falsify post acceptance and readback guards without editing retained evidence."""

import copy
import typing as typ
from unittest import mock

import pytest
from test_news_post_capture_properties import retained_events, verifier


def alter_new_rows(
    change: str, before: list[dict[str, typ.Any]], rows: list[dict[str, typ.Any]]
) -> list[dict[str, typ.Any]]:
    """Alter the added row while preserving all earlier rows.

    Returns
    -------
    list[dict[str, typing.Any]]
        The selected falsification of the after listing.
    """
    if change == "no_added_row":
        return before
    ids = {row["id"] for row in before}
    altered = copy.deepcopy(rows)
    added = next(row for row in altered if row["id"] not in ids)
    match change:
        case "parent" | "flags":
            added[change] += 1
        case "title":
            added[change] = b"wrong title"
        case "flavours":
            added[change] = []
    return altered


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("ack", "one accepted post"),
        ("no_added_row", "one accepted post"),
        ("parent", "new listed root"),
        ("flags", "new listed root"),
        ("title", "new listed root"),
        ("flavours", "new listed root"),
    ],
)
def test_replay_rejects_false_new_post(change: str, reason: str) -> None:
    """A post requires one successful acknowledgement and one matching root."""
    module = verifier()
    cases = retained_events()
    selected = cases["334-zero"]
    original_listing = module.listing
    original_pair = module.pair

    def listing(events: list[dict[str, typ.Any]], action: int) -> object:
        """Falsify only the first post's after listing.

        Returns
        -------
        object
            The original or altered listing tuple.
        """
        path, payload, rows = original_listing(events, action)
        if events is not selected or action != 11:
            return path, payload, rows
        if change == "ack":
            return path, payload, rows
        before = original_listing(events, 7)[2]
        return path, payload, alter_new_rows(change, before, rows)

    def pair(events: list[dict[str, typ.Any]], action: int, transaction: int) -> object:
        """Falsify only the first post acknowledgement.

        Returns
        -------
        object
            The original or altered request and reply.
        """
        request, reply = original_pair(events, action, transaction)
        if (change, action, transaction) == ("ack", 9, 410) and events is selected:
            reply = {**reply, "error": 1}
        return request, reply

    with (
        mock.patch.object(
            module, "check_session", side_effect=lambda case, *_: cases[case]
        ),
        mock.patch.object(module, "listing", side_effect=listing),
        mock.patch.object(module, "pair", side_effect=pair),
        pytest.raises(ValueError, match=rf"^{reason}$"),
    ):
        module.replay()


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("continuity", "continuity between postings"),
        ("category", "category path"),
    ],
)
def test_replay_rejects_listing_ownership(change: str, reason: str) -> None:
    """Successive category listings must preserve path and previous bytes."""
    module = verifier()
    cases = retained_events()
    first = cases["334-zero"]
    second = cases["326-absent"]
    original_listing = module.listing

    def listing(events: list[dict[str, typ.Any]], action: int) -> object:
        """Change one category path or prior listing payload.

        Returns
        -------
        object
            The original or altered listing tuple.
        """
        path, payload, rows = original_listing(events, action)
        if (change, action) == ("continuity", 7) and events is second:
            payload = bytes(10)
        if (change, action) == ("category", 11) and events is first:
            path = b"different category"
        return path, payload, rows

    with (
        mock.patch.object(
            module, "check_session", side_effect=lambda case, *_: cases[case]
        ),
        mock.patch.object(module, "listing", side_effect=listing),
        pytest.raises(ValueError, match=rf"^{reason}$"),
    ):
        module.replay()


@pytest.mark.parametrize(
    ("change", "reason"),
    [
        ("read_id", "read listed ID"),
        ("read_bytes", "posted body readback"),
    ],
)
def test_replay_rejects_body_ownership(change: str, reason: str) -> None:
    """The body read must use the newly listed ID and posted bytes."""
    module = verifier()
    cases = retained_events()
    body = cases["body-334-zero"]
    original_pair = module.pair

    def pair(events: list[dict[str, typ.Any]], action: int, transaction: int) -> object:
        """Change one body read's item ID or content bytes.

        Returns
        -------
        object
            The original or altered request and reply.
        """
        request, reply = original_pair(events, action, transaction)
        if events is body and action == 7:
            if change == "read_id":
                request = {
                    **request,
                    326: (int.from_bytes(request[326], "big") + 1).to_bytes(4, "big"),
                }
            if change == "read_bytes":
                reply = copy.deepcopy(reply)
                field = next(item for item in reply["fields"] if item["id"] == 333)
                field["hex"] = "00"
        return request, reply

    with (
        mock.patch.object(
            module, "check_session", side_effect=lambda case, *_: cases[case]
        ),
        mock.patch.object(module, "pair", side_effect=pair),
        pytest.raises(ValueError, match=rf"^{reason}$"),
    ):
        module.replay()
