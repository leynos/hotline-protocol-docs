"""Check the scalar controls, the article lists, bodies and deletion replies.

These checks are the per-case part of article deletion. They are re-exported by
``verify_native_article_deletion``, which the tests and the verifiers of other
families import by name.
"""

from native_news_decode import articles
from native_wire_names import TYPE_PRIVILEGES_NOTIFICATION
from verify_native_article_deletion_data import (
    BODY_ERROR,
    BOUNDED_WAIT_NS,
    CATEGORY_ERROR,
    DENIED_ERROR,
    ID_ERROR,
    LOW_READ_ERROR,
    TITLES,
    TREES,
)
from verify_native_auth import ADMIN, reply
from verify_native_core import require
from verify_native_shx import fields


def scalar_controls(specifications: list[dict]) -> None:
    """Check that the parent specifications carry the retained scalar controls.

    Parameters
    ----------
    specifications : list[dict]
        The specifications from ``native_news_delete_cases.specs``.
    """
    expected = {
        "absent": (None, False),
        "empty": ("", False),
        "one-zero": ("00", False),
        "two-zero": ("0000", False),
        "four-zero": ("00000000", False),
        "one-one": ("01", True),
        "one-two": ("02", True),
        "one-ff": ("ff", True),
        "two-one": ("0001", True),
        "two-high": ("8000", True),
        "four-high": ("00010000", True),
        "three-one": ("000001", False),
        "five-one": ("00000001ff", True),
        "five-zero": ("00000000ff", False),
    }
    actual = {
        s["case"].removeprefix("parent-"): (
            s["value_hex"],
            s["mode"] == "recursive-parent",
        )
        for s in specifications
        if s["case"].startswith("parent-")
    }
    require(actual == expected, "Deletion scalar controls differ")


def graph(mode: str) -> tuple[list[int], dict[int, tuple[int, int, int, int]]]:
    """Return the traversal order and the links of an expected tree.

    Parameters
    ----------
    mode : str
        The key of the tree in ``TREES``.

    Returns
    -------
    tuple[list[int], dict[int, tuple[int, int, int, int]]]
        The identifiers in traversal order, and for each identifier its previous
        sibling, next sibling, parent and first child, with zero for none.
    """
    roots, children = TREES[mode]
    order, links = [], {}

    def visit(siblings: list[int], parent: int) -> None:
        """Link each sibling to its neighbours and its descendants in order.

        Parameters
        ----------
        siblings : list[int]
            The identifiers that share one parent, in order.
        parent : int
            The identifier of their parent, or zero for the roots.
        """
        for index, identifier in enumerate(siblings):
            descendants = children.get(identifier, [])
            links[identifier] = (
                siblings[index - 1] if index else 0,
                siblings[index + 1] if index + 1 < len(siblings) else 0,
                parent,
                descendants[0] if descendants else 0,
            )
            order.append(identifier)
            visit(descendants, identifier)

    visit(roots, 0)
    return order, links


def list_records(value: bytes, mode: str) -> dict[int, dict]:
    """Decode an article list and check its order and metadata against a tree.

    Parameters
    ----------
    value : bytes
        The article-list field of a reply.
    mode : str
        The key of the expected tree in ``TREES``.

    Returns
    -------
    dict[int, dict]
        The decoded articles keyed by identifier.
    """
    rows = articles(value)
    order, links = graph(mode)
    require([r["id"] for r in rows] == order, "Deletion traversal differs")
    for row in rows:
        identifier = row["id"]
        require(
            row["title"] == TITLES[identifier]
            and row["poster"] == b"framing-fixture"
            and row["parent"] == links[identifier][2]
            and row["flags"] == 0
            and row["flavours"] == [(b"text/plain", 6)]
            and row["date"][:4] == b"\x07p\0\0"
            and row["date"][4:] != bytes(4),
            "Deletion article metadata differs",
        )
    return {r["id"]: r for r in rows}


def error(frame: dict, message: bytes) -> None:
    """Check that a reply is the error reply with the given text.

    Parameters
    ----------
    frame : dict
        The reply frame.
    message : bytes
        The expected error text.
    """
    require(
        frame["error"] == 1 and fields(frame) == {100: message},
        "Deletion error differs",
    )


def body(frame: dict, identifier: int, rows: dict[int, dict], mode: str) -> None:
    """Check the body and the navigation fields of one article reply.

    Parameters
    ----------
    frame : dict
        The reply frame.
    identifier : int
        The article that was requested.
    rows : dict[int, dict]
        The articles that the list shows, keyed by identifier.
    mode : str
        The key of the expected tree in ``TREES``.
    """
    if identifier not in rows:
        error(frame, BODY_ERROR)
        return
    _, links = graph(mode)
    expected = {
        333: b"body-" + TITLES[identifier],
        328: TITLES[identifier],
        329: b"framing-fixture",
        327: b"text/plain",
        330: rows[identifier]["date"],
        **{
            key: n.to_bytes(2, "big")
            for key, n in zip([331, 332, 335, 336], links[identifier], strict=True)
        },
    }
    require(
        frame["error"] == 0 and fields(frame) == expected,
        "Deletion body/navigation differs",
    )


def measured_wait(report: dict, operation: str) -> None:
    """Check that a report holds one bounded pacing or quiet window.

    This function is imported by other verifiers; its signature and behaviour are
    fixed.

    Parameters
    ----------
    report : dict
        The parsed ``report.json`` of a capture.
    operation : str
        ``"expect_quiet"`` for the quiet window, anything else for the pause.
    """
    event_name = "quiet" if operation == "expect_quiet" else "pause"
    events = report["events"]
    found = [i for i, e in enumerate(events) if e["event"] == event_name]
    require(len(found) == 1 and found[0] > 0, "Missing bounded pacing/quiet event")
    index = found[0]
    require(
        events[index]["elapsed_ns"] - events[index - 1]["elapsed_ns"]
        >= BOUNDED_WAIT_NS,
        "Short bounded pacing/quiet observation",
    )


def _check_removal(report: dict, case: str) -> None:
    """Check the reply to the deletion request of one case.

    Parameters
    ----------
    report : dict
        The parsed ``report.json`` of the deletion capture.
    case : str
        The case name, which selects the expected reply.
    """
    match case:
        case "missing-id" | "missing-id-field":
            error(reply(report, 11), ID_ERROR)
        case "missing-category":
            error(reply(report, 11), CATEGORY_ERROR)
        case "denied":
            error(reply(report, 11), DENIED_ERROR)
        case _:
            require(
                reply(report, 11)["error"] == 0 and fields(reply(report, 11)) == {},
                "Deletion ACK differs",
            )


def deletion(report: dict, spec: dict) -> bytes:
    """Check one deletion capture and return the list that follows it.

    Parameters
    ----------
    report : dict
        The parsed ``report.json`` of the deletion capture.
    spec : dict
        The specification of the case, from ``native_news_delete_cases.specs``.

    Returns
    -------
    bytes
        The article-list field of the reply after the deletion.
    """
    before = list_records(fields(reply(report, 10))[321], "unchanged")
    after_value = fields(reply(report, 20))[321]
    after = list_records(after_value, spec["mode"])
    require(
        fields(reply(report, 21)) == {321: after_value}, "Repeated cached list differs"
    )
    require(
        all(row["date"] == before[i]["date"] for i, row in after.items()),
        "Deletion changed surviving dates",
    )
    _check_removal(report, spec["case"])
    if spec["repeat"]:
        error(reply(report, 12), ID_ERROR)
    access = next(
        f for f in report["frames"] if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
    )
    require(
        fields(access) == {110: bytes(8) if spec["role"] == "low" else ADMIN},
        "Deletion access mask differs",
    )
    if spec["role"] == "low":
        error(reply(report, 101), LOW_READ_ERROR)
    else:
        for identifier in TITLES:
            body(reply(report, 100 + identifier), identifier, after, spec["mode"])
    require(
        reply(report, 90)["error"] == 0 and fields(reply(report, 90)) == {},
        "Deletion lost liveness",
    )
    measured_wait(report, "expect_quiet")
    return after_value
