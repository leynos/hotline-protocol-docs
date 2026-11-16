"""Pin which error the Classic login proxy's functions raise first.

``classic_login_proxy`` was restructured, so the order in which its checks run is
held here, outside ``scripts/tests``, whose tests are the golden keys.
``data/classic_proxy_error_order.tsv`` records, for each case below, how the call
ended on the scripts as they stood before the restructuring (commit 8a3f8cd):
the exception type and message, or ``ok`` and a digest of the result. A case that
combines two faults shows which check runs first. Regenerate the table only from
the earlier scripts, never from the current ones.
"""

import socket
import struct
import time
import typing as typ
from pathlib import Path
from unittest import mock

import pytest
from classic_login_proxy import (
    Audit,
    ObservationWatchdog,
    RosterState,
    namespace_guard,
    parse_frame,
    read_frame,
    relay_frames,
    transform_ack,
)
from mutation_support import ending

if typ.TYPE_CHECKING:
    import collections.abc as cabc

TABLE = Path(__file__).with_name("data") / "classic_proxy_error_order.tsv"
LOGIN_ID = 7
ACK_FIELDS = [(160, b"\x00\xbe"), (161, b"\x00\x00"), (162, b"Name")]
FRAME_HEADER = ">BBHIIII"
OVERSIZE = 65536
NAMESPACE = 4026532479
HOST_NAMESPACE = 4026531840
FUTURE = 10**9


def frame(fields: list[tuple[int, bytes]], **header: int) -> bytes:
    """Build a control frame whose header can be made to disagree with its body.

    The header values are ``kind``, ``identifier``, ``reply``, ``flags``,
    ``error`` and ``total``; a value that is not given is that of a successful
    reply to the login, and ``total`` is the length of the body.

    Returns
    -------
    bytes
        The frame.
    """
    body = struct.pack(">H", len(fields)) + b"".join(
        struct.pack(">HH", key, len(value)) + value for key, value in fields
    )
    values = {"kind": 0, "identifier": LOGIN_ID, "reply": 1, "flags": 0, "error": 0}
    values |= {"total": len(body)} | header
    head = struct.pack(
        FRAME_HEADER,
        values["flags"],
        values["reply"],
        values["kind"],
        values["identifier"],
        values["error"],
        values["total"],
        len(body),
    )
    return head + body


def ack(fields: list[tuple[int, bytes]] | None = None, **header: int) -> bytes:
    """Build a Login107 ACK, with fields and header values changed as asked.

    Returns
    -------
    bytes
        The frame.
    """
    return frame(ACK_FIELDS if fields is None else fields, **header)


def lying_count() -> bytes:
    """Build a frame that declares three fields and holds two.

    Returns
    -------
    bytes
        The frame.
    """
    good = ack(ACK_FIELDS[:2])
    return good[:20] + struct.pack(">H", 3) + good[22:]


def transform(raw: bytes, variant: str, login: int = LOGIN_ID) -> object:
    """Run ``transform_ack`` and digest its result.

    Returns
    -------
    object
        The rewritten frame.
    """
    return transform_ack(raw, login, variant).hex()


def roster_reply(fields: list[tuple[int, bytes]]) -> object:
    """Offer a reply to a roster that has seen the first 300 request.

    Returns
    -------
    object
        What ``rewrite_reply`` forwarded.
    """
    state = RosterState()
    state.observe_client(frame([], kind=300, identifier=3, reply=0))
    return state.rewrite_reply(frame(fields, identifier=3)).hex()


def audit_check(*, cutoff: bool, late: bool, abort: bool) -> object:
    """Set the three stop conditions of an audit and check it.

    Returns
    -------
    object
        ``None`` when no condition is set.
    """
    audit = Audit(time.monotonic() - 1 if late else time.monotonic() + FUTURE)
    for flag, event in ((cutoff, audit.cutoff), (abort, audit.abort)):
        if flag:
            event.set()
    return audit.check()


def arm_twice(*, stopped: bool) -> object:
    """Arm a watchdog twice, with or without a stopped audit.

    Returns
    -------
    object
        What the second arming raised, if anything.
    """
    audit = Audit(time.monotonic() + FUTURE)
    dog = ObservationWatchdog(audit, lambda: None)
    dog.arm(b"a", b"b")
    if stopped:
        audit.abort.set()
    return dog.arm(b"c", b"d")


def oversize_frame() -> object:
    """Read a frame that declares more than the bound, with no body behind it.

    Returns
    -------
    object
        What ``read_frame`` raised.
    """
    one, two = socket.socketpair()
    with one, two:
        one.sendall(b"\x00" * 16 + struct.pack(">I", OVERSIZE))
        two.settimeout(0.25)
        return read_frame(two, Audit(time.monotonic() + FUTURE))


def relay_without_ack(login_id: int | None, *, pending: bool) -> object:
    """Relay the server side of a stream that holds nothing, or one bad frame.

    Returns
    -------
    object
        What ``relay_frames`` raised, if anything.
    """
    source, target = socket.socketpair()
    with source, target:
        if pending:
            target.sendall(ack())
        target.shutdown(socket.SHUT_WR)
        source.settimeout(0.25)
        return relay_frames(
            source,
            target,
            Audit(time.monotonic() + FUTURE),
            "server",
            login_id,
            "baseline",
        )


def guard(
    expected: int, host: int, *, own: int = NAMESPACE, names: tuple[str, ...] = ("lo",)
) -> object:
    """Run ``namespace_guard`` against a stand-in for the namespace.

    Returns
    -------
    object
        What the guard returned or raised.
    """
    stat = mock.Mock(return_value=mock.Mock(st_ino=own))
    interfaces = list(enumerate(names, 1))
    with (
        mock.patch("os.stat", stat),
        mock.patch("socket.if_nameindex", return_value=interfaces),
        mock.patch("subprocess.run") as run,
    ):
        run.return_value.stdout = "[]"
        return namespace_guard(expected, host)


CASES: dict[str, cabc.Callable[[], object]] = {
    "transform-unknown-variant": lambda: transform(ack(), "nope"),
    "transform-unknown-variant-and-short": lambda: transform(b"short", "nope"),
    "transform-short": lambda: transform(b"short", "baseline"),
    "transform-total-differs": lambda: transform(ack(total=1), "baseline"),
    "transform-bad-reply-flag": lambda: transform(ack(reply=2), "baseline"),
    "transform-lying-count": lambda: transform(lying_count(), "baseline"),
    "transform-lying-count-and-request": lambda: transform(
        lying_count()[:1] + b"\x00" + lying_count()[2:], "baseline"
    ),
    "transform-request-not-ack": lambda: transform(ack(reply=0), "baseline"),
    "transform-other-id": lambda: transform(ack(identifier=8), "baseline"),
    "transform-error-set": lambda: transform(ack(error=1), "baseline"),
    "transform-no-161": lambda: transform(ack([(160, b"\x00\xbe")]), "baseline"),
    "transform-wrong-161": lambda: transform(
        ack([(161, b"\x00\x01")]), "server-name-162"
    ),
    "transform-wrong-161-and-other-id": lambda: transform(
        ack([(161, b"\x00\x01")], identifier=8), "baseline"
    ),
    "transform-162-present-and-wrong-161": lambda: transform(
        ack([(161, b"\x00\x01"), (162, b"x")]), "server-name-162"
    ),
    "transform-162-present": lambda: transform(ack(), "server-name-162"),
    "transform-baseline": lambda: transform(ack([(161, b"\x00\x00")]), "baseline"),
    "transform-baseline-flags": lambda: transform(
        ack([(161, b"\x00\x00")], flags=1), "baseline"
    ),
    "transform-omit": lambda: transform(ack(), "omit-161"),
    "transform-one-byte": lambda: transform(ack(), "one-byte-161"),
    "transform-four-byte": lambda: transform(ack(), "four-byte-161"),
    "transform-server-name": lambda: transform(
        ack([(160, b"\x00\xbe"), (161, b"\x00\x00")]), "server-name-162"
    ),
    "transform-roster": lambda: transform(ack(), "roster-subject-115"),
    "parse-short": lambda: parse_frame(b"short"),
    "parse-fine": lambda: parse_frame(ack()),
    "roster-no-records": lambda: roster_reply([(115 + 1, b"x")]),
    "roster-has-115": lambda: roster_reply([
        (300, b"\0" * 6 + b"\x00\x01x"),
        (115, b""),
    ]),
    "roster-short-record": lambda: roster_reply([(300, b"\0\0")]),
    "roster-length-differs": lambda: roster_reply([(300, b"\0" * 6 + b"\x00\x02x")]),
    "roster-empty-name": lambda: roster_reply([(300, b"\0" * 6 + b"\x00\x00")]),
    "roster-short-then-bad-length": lambda: roster_reply([
        (300, b"\0\0"),
        (300, b"\0" * 6 + b"\x00\x02x"),
    ]),
    "roster-ok": lambda: roster_reply([(300, b"\0" * 6 + b"\x00\x01x")]),
    "audit-cutoff-late-abort": lambda: audit_check(cutoff=True, late=True, abort=True),
    "audit-late-abort": lambda: audit_check(cutoff=False, late=True, abort=True),
    "audit-abort": lambda: audit_check(cutoff=False, late=False, abort=True),
    "audit-cutoff-abort": lambda: audit_check(cutoff=True, late=False, abort=True),
    "audit-quiet": lambda: audit_check(cutoff=False, late=False, abort=False),
    "watchdog-armed-twice": lambda: arm_twice(stopped=False),
    "watchdog-armed-twice-after-abort": lambda: arm_twice(stopped=True),
    "read-oversize": oversize_frame,
    "relay-no-login-id": lambda: relay_without_ack(None, pending=True),
    "relay-empty": lambda: relay_without_ack(LOGIN_ID, pending=False),
    "guard-equal": lambda: guard(NAMESPACE, NAMESPACE),
    "guard-zero": lambda: guard(0, HOST_NAMESPACE),
    "guard-own-differs": lambda: guard(NAMESPACE, HOST_NAMESPACE, own=1),
    "guard-own-is-host": lambda: guard(NAMESPACE, HOST_NAMESPACE, own=HOST_NAMESPACE),
    "guard-extra-interface": lambda: guard(
        NAMESPACE, HOST_NAMESPACE, names=("lo", "x")
    ),
    "guard-ok": lambda: guard(NAMESPACE, HOST_NAMESPACE),
}


def read_expected() -> dict[str, str]:
    """Read the recorded endings.

    Returns
    -------
    dict[str, str]
        The ending of each case.
    """
    lines = TABLE.read_text().splitlines()
    return {name: expected for name, _, expected in (x.partition("\t") for x in lines)}


class ClassicProxyErrorOrderTests:
    """Keep the proxy's checks in the order in which they have run."""

    @pytest.mark.parametrize("name", sorted(CASES))
    def test_each_case_ends_as_it_did(self, name: str) -> None:
        """Each case ends with the exception or result recorded earlier."""
        expected = read_expected()
        assert name in expected, "case has no recorded ending"
        assert ending(lambda _state: CASES[name](), None) == expected[name], "differs"


def record() -> None:
    """Print the table of endings; run it only on the earlier scripts."""
    for name in sorted(CASES):
        print(f"{name}\t{ending(lambda _state, n=name: CASES[n](), None)}")
