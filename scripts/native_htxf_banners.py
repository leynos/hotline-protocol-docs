"""Plan the banner download observations of the HTXF cases."""

from native_htxf_steps import (
    LOW_FINAL_PUMP_ID,
    LOW_PUMP_ID,
    PUMP_ID,
    RESERVED_ANY,
    SIZE_ANY,
    Cases,
    attach,
    data,
    header,
    low_session,
    quiet,
    request,
)
from native_plan import (
    close,
    connect,
    eof,
    send,
)
from native_queue_cases import Case, pump, session
from native_wire_names import (
    HTXF_MAGIC_HEX,
)


def header_cases() -> Cases:
    """Plan the banner downloads whose header words are unusual.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The three header cases, the last of which has a bad magic.
    """
    cases = {}
    for name, size, reserved, magic in [
        ("size-ffffffff-reserved-ffff", SIZE_ANY, RESERVED_ANY, HTXF_MAGIC_HEX),
        ("size-one-reserved-1234", 1, 0x1234, HTXF_MAGIC_HEX),
        ("bad-magic", 0, 0, "48545847"),
    ]:
        steps = [
            *session("a"),
            *request(),
            *attach("data", size=size, reserved=reserved, magic=magic),
        ]
        steps += (
            [eof("data")] if name == "bad-magic" else [*data("data"), quiet("data")]
        )
        steps += [close("data"), *pump("a", PUMP_ID), close("a")]
        cases["banner-" + name] = (
            steps,
            {
                "kind": "banner-header",
                "size": size,
                "reserved": reserved,
                "magic": magic,
                "accepted": name != "bad-magic",
            },
        )
    return cases


def split_case() -> Case:
    """Plan a header that arrives in two pieces, with a silence between.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    whole = header(reserved=0x1234)
    steps = [
        *session("a"),
        *request(),
        connect("data", "data"),
        send(whole[:-2], "data"),
        quiet("data"),
        send(whole[-2:], "data"),
        *data("data"),
        quiet("data"),
        close("data"),
        *pump("a", PUMP_ID),
        close("a"),
    ]
    return steps, {"kind": "split-header"}


def foreign_case() -> Case:
    """Plan an attachment by a second, low-privilege session.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [
        *session("a"),
        *low_session(),
        *request(),
        *attach("foreign"),
        *data("foreign"),
        quiet("foreign"),
        close("foreign"),
        *pump("a", PUMP_ID),
        *pump("b", LOW_PUMP_ID, seconds=0),
        close("a"),
        *pump("b", LOW_FINAL_PUMP_ID),
        close("b"),
    ]
    return steps, {"kind": "cross-session"}


def owner_gone_case() -> Case:
    """Plan an attachment after the owning session has closed.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [
        *session("a"),
        *low_session(),
        *request(),
        close("a"),
        *pump("b", PUMP_ID),
        *attach("stale"),
        eof("stale"),
        close("stale"),
        close("b"),
    ]
    return steps, {"kind": "owner-gone"}


def reuse_case() -> Case:
    """Plan a second attachment with a reference that has been used and closed.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [
        *session("a"),
        *request(),
        *attach("first"),
        *data("first"),
        close("first"),
        *pump("a", PUMP_ID),
        *attach("stale"),
        eof("stale"),
        close("stale"),
        close("a"),
    ]
    return steps, {"kind": "reuse-after-close"}


def duplicate_case() -> Case:
    """Plan a second attachment while the first is still open.

    Returns
    -------
    tuple[list[native_plan.Action], dict[str, typing.Any]]
        The steps and the expectation.
    """
    steps = [
        *session("a"),
        *low_session(),
        *request(),
        *attach("first"),
        *data("first"),
        quiet("first"),
        *attach("second"),
        quiet("second"),
        close("a"),
        *pump("b", PUMP_ID),
        eof("second"),
        quiet("first"),
        close("second"),
        close("first"),
        close("b"),
    ]
    return steps, {"kind": "duplicate-after-send"}


def banners() -> Cases:
    """Plan the banner download observations.

    Returns
    -------
    dict[str, tuple[list[native_plan.Action], dict[str, typing.Any]]]
        The cases keyed ``banner-`` and a name.
    """
    return {
        **header_cases(),
        "banner-split-15-plus-1": split_case(),
        "banner-separate-low-privilege-session": foreign_case(),
        "banner-owner-gone": owner_gone_case(),
        "banner-reuse-after-close": reuse_case(),
        "banner-duplicate-after-send": duplicate_case(),
    }
