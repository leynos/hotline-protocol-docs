"""Pin the order of the bitmap verifier's semantic checks.

The goldens observe only the retained corpus, so the order in which an unsound
set of reports is refused is held here, outside ``scripts/tests``, whose tests
are the golden keys. Every expectation was observed on the version of the
scripts before the verifier was split into ``verify_native_bitmap_checks``
(commit 0b34126).

A set of reports that breaks check ``n`` also breaks every check after it, so
the message that comes back names the first check that the verifier makes.
"""

import copy
import json
import typing as typ
from pathlib import Path

import native_bitmap_cases as cases
import pytest
from native_auth_cases import complement
from verify_native_bitmaps import semantic

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]
type Reports = dict[str, Report]

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-bitmaps-01"
)
ACCESS_FIELD = 110
PRIVILEGES = 354
FIRST_UPDATE_ID = 20
FIRST_READ_ID = 21
SECOND_READ_ID = 23
FIRST_WIDTH_UPDATE_ID = 40
READ_TYPE = 352
LOGIN_TYPE = 107
WRONG_BIT = "4000000000000000"
FIRST_BIT = "8000000000000000"
WRONG_ERROR = 1
WALKING_BITS = 64
HEADER_BYTES = 8  # the type and the ID are in the first eight bytes of a frame


def reports() -> Reports:
    """Load the report of every suite in the retained corpus.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        The reports, by suite name.
    """
    return {
        name: json.loads((CORPUS / name / "report.json").read_text())
        for name in cases.suites()
    }


def reply(report: Report, identifier: int, connection: str = "main") -> Report:
    """Find the reply with ``identifier`` that ``connection`` received.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    return next(
        f
        for f in report["frames"]
        if f["connection"] == connection and f["is_reply"] and f["id"] == identifier
    )


def header(event: Report) -> tuple[int, int] | None:
    """Read the type and ID of the request that a send event carries.

    Returns
    -------
    tuple[int, int] | None
        The type and the identifier, or none for an event that is not a request.
    """
    raw = bytes.fromhex(event["hex"]) if event["event"] == "send" else b""
    if len(raw) < HEADER_BYTES:
        return None
    return int.from_bytes(raw[2:4], "big"), int.from_bytes(raw[4:8], "big")


def request(report: Report, kind: int, identifier: int, connection: str) -> Report:
    """Find the send event of the request with ``kind`` and ``identifier``.

    Returns
    -------
    dict[str, typing.Any]
        The event.
    """
    return next(
        e
        for e in report["events"]
        if e["event"] == "send"
        and e["connection"] == connection
        and header(e) == (kind, identifier)
    )


type Break = cabc.Callable[[Reports], None]
type Chain = list[tuple[str, str, Break]]


def missing_suite(rs: Reports) -> None:
    """Leave one suite out of the reports."""
    del rs["cleanup"]


def short_inventory(rs: Reports) -> None:
    """Leave one account out of the preflight enumeration."""
    reply(rs["preflight"], 10)["fields"].pop()


def present_account(rs: Reports) -> None:
    """Make the preflight read of the owned account succeed."""
    reply(rs["preflight"], 11)["error"] = 0


def failed_seed(rs: Reports) -> None:
    """Make the creation of the owned account fail."""
    reply(rs["seed"], 10)["error"] = WRONG_ERROR


def wrong_seed_readback(rs: Reports) -> None:
    """Change the bitmap that the seed readback returned."""
    frame = reply(rs["seed"], 11)
    next(f for f in frame["fields"] if f["id"] == ACCESS_FIELD)["hex"] = FIRST_BIT


def swap_readbacks(report: Report, first: int, second: int) -> None:
    """Swap the replies with the identifiers ``first`` and ``second``."""
    frames = report["frames"]
    a = next(i for i, f in enumerate(frames) if f["is_reply"] and f["id"] == first)
    b = next(i for i, f in enumerate(frames) if f["is_reply"] and f["id"] == second)
    frames[a], frames[b] = frames[b], frames[a]


def swapped_readbacks(rs: Reports) -> None:
    """Swap two readbacks of the first walk."""
    swap_readbacks(rs["walk-00"], FIRST_READ_ID, SECOND_READ_ID)


def wrong_submitted(rs: Reports) -> None:
    """Change the bitmap that the first walk request sent."""
    event = request(rs["walk-00"], 353, FIRST_UPDATE_ID, "main")
    event["hex"] = event["hex"].replace(FIRST_BIT, WRONG_BIT)


def failed_replacement(rs: Reports) -> None:
    """Make the first walk replacement fail."""
    reply(rs["walk-00"], FIRST_UPDATE_ID)["error"] = WRONG_ERROR


def other_identity_read(rs: Reports) -> None:
    """Change the identity that the first walk readback asked for."""
    event = request(rs["walk-00"], READ_TYPE, FIRST_READ_ID, "main")
    event["hex"] = event["hex"].replace(cases.KEY.hex(), cases.KEY[:-1].hex() + "58")


def other_credentials(rs: Reports) -> None:
    """Change the login that the all-ones session sent."""
    event = request(rs["all-ones"], LOGIN_TYPE, 1, "owned")
    event["hex"] = event["hex"].replace(
        complement(cases.KEY).hex(), complement(cases.KEY[:-1] + b"X").hex()
    )


def duplicated_push(rs: Reports) -> None:
    """Give the all-ones session a second privilege push."""
    frames = rs["all-ones"]["frames"]
    push = next(
        f for f in frames if f["connection"] == "owned" and f["type"] == PRIVILEGES
    )
    frames.append(copy.deepcopy(push))


def kept_account(rs: Reports) -> None:
    """Make the cleanup deletion fail."""
    reply(rs["cleanup"], 10)["error"] = WRONG_ERROR


CHAIN: Chain = [
    ("inventory", "Bitmap case inventory differs", missing_suite),
    ("preflight", "Preflight account inventory differs", short_inventory),
    ("absence", "Owned account was not proven absent", present_account),
    ("seed", "Owned account seed differs", failed_seed),
    (
        "seed readback",
        "Owned account identity/bitmap/password readback differs",
        wrong_seed_readback,
    ),
    ("order", "Bitmap replacement/readback order differs", swapped_readbacks),
    ("submitted", "Wrong submitted bitmap/owned replacement fields", wrong_submitted),
    ("replacement", "Bitmap replacement failed", failed_replacement),
    (
        "identity",
        "Account readback requested another identity",
        other_identity_read,
    ),
    ("credentials", "All-ones subject used other credentials", other_credentials),
    ("push", "All-ones effective session bitmap differs", duplicated_push),
    ("cleanup", "Owned account cleanup/baseline differs", kept_account),
]


class SemanticOrderTests:
    """Keep the semantic checks in the order in which they have run."""

    def test_the_retained_reports_are_accepted(self) -> None:
        """The retained reports pass every check."""
        result = semantic(reports())
        assert result["walking_bits_verified"] == WALKING_BITS, "not accepted"

    @pytest.mark.parametrize("first", range(len(CHAIN)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        rs = reports()
        for _label, _message, apply in reversed(CHAIN[first:]):
            apply(rs)
        _label, message, _apply = CHAIN[first]
        with pytest.raises(ValueError, match=message):
            semantic(rs)

    def test_the_walks_are_checked_before_the_widths(self) -> None:
        """A failed walk replacement is reported before a misordered width run."""
        rs = reports()
        failed_replacement(rs)
        swap_readbacks(rs["widths"], 41, 43)
        with pytest.raises(ValueError, match="Bitmap replacement failed"):
            semantic(rs)

    def test_the_width_order_is_checked_before_the_width_replacements(self) -> None:
        """A misordered width run is reported before a failed width replacement."""
        rs = reports()
        reply(rs["widths"], FIRST_WIDTH_UPDATE_ID)["error"] = WRONG_ERROR
        swap_readbacks(rs["widths"], 41, 43)
        with pytest.raises(ValueError, match="order differs"):
            semantic(rs)
        swap_readbacks(rs["widths"], 41, 43)
        with pytest.raises(ValueError, match="Bitmap replacement failed"):
            semantic(rs)

    def test_the_widths_are_checked_before_the_all_ones_session(self) -> None:
        """A failed width replacement is reported before the all-ones credentials."""
        rs = reports()
        other_credentials(rs)
        reply(rs["widths"], FIRST_WIDTH_UPDATE_ID)["error"] = WRONG_ERROR
        with pytest.raises(ValueError, match="Bitmap replacement failed"):
            semantic(rs)

    def test_the_all_ones_replacement_is_checked_before_its_credentials(self) -> None:
        """A failed all-ones replacement is reported before its credentials."""
        rs = reports()
        other_credentials(rs)
        reply(rs["all-ones"], 10)["error"] = WRONG_ERROR
        with pytest.raises(ValueError, match="Bitmap replacement failed"):
            semantic(rs)

    def test_each_walk_group_is_checked_in_order(self) -> None:
        """The first group that fails is the one reported."""
        rs = reports()
        swap_readbacks(rs["walk-05"], FIRST_READ_ID, SECOND_READ_ID)
        with pytest.raises(ValueError, match="order differs"):
            semantic(rs)
        reply(rs["walk-03"], FIRST_UPDATE_ID)["error"] = WRONG_ERROR
        with pytest.raises(ValueError, match="Bitmap replacement failed"):
            semantic(rs)
