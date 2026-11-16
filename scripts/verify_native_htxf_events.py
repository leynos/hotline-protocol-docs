"""Check the quiet intervals and the order of events in a recorded HTXF case.

The order of the checks in each function is the order in which a corrupt case
is refused.
"""

import typing as typ

from verify_native_core import require

type Report = dict[str, typ.Any]

QUIET_NS = 3_000_000_000  # the shortest accepted quiet observation
SPLIT_SENDS = [15, 1]  # the split header goes out as 15 bytes and then 1


def observed(report: Report, connection: str, event: str) -> list[Report]:
    """List the events of one kind on one connection.

    Returns
    -------
    list[dict[str, typing.Any]]
        The matching events, in order.
    """
    return [
        e
        for e in report["events"]
        if e["connection"] == connection and e["event"] == event
    ]


def check_quiet_windows(report: Report) -> None:
    """Check that each quiet observation ran for at least three seconds."""
    for e in report["events"]:
        if e["event"] == "quiet":
            before = max(
                p["elapsed_ns"] for p in report["events"] if p["action"] < e["action"]
            )
            require(
                e["elapsed_ns"] - before >= QUIET_NS, "Short HTXF quiet observation"
            )


def check_split(report: Report) -> None:
    """Check the split header's two sends and the quiet interval between them."""
    sends = observed(report, "data", "send")
    require(
        [len(bytes.fromhex(e["hex"])) for e in sends] == SPLIT_SENDS,
        "Split header differs",
    )
    require(
        any(
            sends[0]["action"] < q["action"] < sends[1]["action"]
            for q in observed(report, "data", "quiet")
        ),
        "Missing incomplete-header quiet interval",
    )


def check_ordering(name: str, report: Report, packets: Report) -> None:
    """Check the case-specific order of closes, attachments and quiet intervals."""
    if name == "banner-split-15-plus-1":
        check_split(report)
    if name in {"banner-owner-gone", "download-owner-gone"}:
        target = "stale" if name.startswith("banner") else "download"
        require(
            observed(report, "a", "close")[0]["action"]
            < observed(report, target, "connect")[0]["action"],
            "Owner was not closed before attachment",
        )
    if name == "banner-reuse-after-close":
        require(
            observed(report, "first", "close")[0]["action"]
            < observed(report, "stale", "connect")[0]["action"],
            "Reference was not reused after close",
        )
    if name == "banner-duplicate-after-send":
        require(
            not packets["first"]["guest_server_initiated_close"],
            "First duplicate transport closed natively",
        )
        end = observed(report, "second", "eof")[0]["action"]
        require(
            observed(report, "a", "close")[0]["action"]
            < end
            < observed(report, "first", "quiet")[-1]["action"],
            "Duplicate cleanup ordering differs",
        )
