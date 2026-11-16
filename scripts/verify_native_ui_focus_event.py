"""Check the focus event: its title pixels, its packet streams and its timing."""

import datetime as dt
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

from verify_native_ui_focus_core import (
    ACTIVATED_GOLD,
    OBSERVE_SECONDS,
    PLATEAU_SECONDS,
    TITLE_BOX,
    load,
    require,
)
from verify_native_ui_focus_png import gold_count, png_rows


def check_focus_images(exp: Path) -> dict[str, typ.Any]:
    """Check the focus-event title pixels and the click target.

    Returns
    -------
    dict[str, typing.Any]
        The focus-event result document.
    """
    before, after = (exp / "focus-event" / name for name in ("before.png", "after.png"))
    before_rows, after_rows = png_rows(before), png_rows(after)
    result = load(exp / "focus-event/result.json")
    require(
        result["event_count"] == 1
        and result["status"] == "no_progress_after_verified_focus",
        "Focus event outcome differs",
    )
    require(
        result["title_gold_before"] == gold_count(before_rows, TITLE_BOX) == 0,
        "Inactive Log title differs",
    )
    require(
        result["title_gold_after"]
        == gold_count(after_rows, TITLE_BOX)
        == ACTIVATED_GOLD,
        "Activated Log title differs",
    )
    require(
        before_rows[180][450 * 3 : 450 * 3 + 3] == b"\xff\xff\xff",
        "Blank Log click target differs",
    )
    return result


def check_focus_streams(
    result: dict[str, typ.Any],
    views: dict[str, dict[str, typ.Any]],
    local: int,
) -> None:
    """Check that each stage of the focus event saw the same packet streams.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The focus-event result document.
    views : dict[str, dict[str, typing.Any]]
        The summary of each recorded capture.
    local : int
        The local port of the download connection.
    """
    for stage in ("before", "after"):
        for name in ("guest", "namespace"):
            item = result[stage][name]
            require(
                item["bytes"] == views[name]["bytes"]
                and item["sha256"] == views[name]["sha256"]
                and item["local_port"] == local,
                f"{stage} {name} event stream differs",
            )
            require(
                item["last_packet_us"] == result["before"][name]["last_packet_us"],
                f"{name} post-event packet tail differs",
            )


def check_timing(result: dict[str, typ.Any]) -> None:
    """Check the plateau before the click and the observation after it.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The focus-event result document.
    """
    start = dt.datetime.fromisoformat(result["started_utc"])
    click = dt.datetime.fromisoformat(result["event_utc"])
    returned = dt.datetime.fromisoformat(result["event_return_utc"])
    ended = dt.datetime.fromisoformat(result["ended_utc"])
    require(
        (click - start).total_seconds() >= PLATEAU_SECONDS
        and (ended - returned).total_seconds() >= OBSERVE_SECONDS,
        "Plateau or observation duration differs",
    )
    for name in ("guest", "namespace"):
        last = dt.datetime.fromtimestamp(
            result["before"][name]["last_packet_us"] / 1_000_000, dt.UTC
        )
        require(
            (click - last).total_seconds() >= PLATEAU_SECONDS,
            f"{name} packet plateau too short",
        )
