"""Pin the order of the ID verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before ``check_outcome``, ``verify`` and ``verify_oracle`` were split into
smaller functions (commit 8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import copy
import json
import typing as typ
from pathlib import Path

import pytest
from native_correlation_cases import correlation
from verify_native_correlation import check_outcome

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-correlation-01"
)
BOOTSTRAP_FRAMES = 3  # the login ACK and its two notifications
WRONG_ID = 9
WRONG_HEX = "ff"
NONZERO_FLAGS = 1
UNSUPPORTED_TYPE = 65535


class Subject:
    """One retained case, its expectation and its packet facts, ready to break."""

    def __init__(self, name: str) -> None:
        """Load the report, the planned expectation and the packet record."""
        self.report: Report = json.loads(
            (BATCH / "transcripts" / name / "report.json").read_text()
        )
        self.expected: Report = correlation()[name][1]
        reconciliation = json.loads((BATCH / "packet-reconciliation.json").read_text())
        self.packets: Report = reconciliation[name]

    def later(self, *, replies: bool) -> list[Report]:
        """List the frames after the bootstrap, replies or notifications.

        Returns
        -------
        list[dict[str, typing.Any]]
            The matching frames, in order.
        """
        return [
            f
            for f in self.report["frames"][BOOTSTRAP_FRAMES:]
            if bool(f["is_reply"]) == replies
        ]

    def check(self) -> Report:
        """Check the subject as the corpus check does.

        Returns
        -------
        dict[str, typing.Any]
            The result of ``check_outcome``.
        """
        return check_outcome(self.report, self.expected, self.packets)


type Break = cabc.Callable[[Subject], None]
type Chain = list[tuple[str, str, Break]]


def broken(name: str, chain: Chain, first: int) -> Subject:
    """Break the case from check ``first`` on, last break first.

    Returns
    -------
    Subject
        The broken case.
    """
    subject = Subject(name)
    for _label, _message, apply in reversed(chain[first:]):
        apply(subject)
    return subject


def incomplete(subject: Subject) -> None:
    """Mark the capture as failed."""
    subject.report["status"] = "failed"


def bad_bootstrap(subject: Subject) -> None:
    """Change the ID of the login ACK."""
    subject.report["frames"][0]["id"] = WRONG_ID


def native_flags(subject: Subject) -> None:
    """Give the last frame a flag word."""
    subject.report["frames"][-1]["flags"] = NONZERO_FLAGS


def extra_reply(subject: Subject) -> None:
    """Add a second direct reply."""
    reply = subject.later(replies=True)[-1]
    subject.report["frames"].append(copy.deepcopy(reply))


def wrong_reply_id(subject: Subject) -> None:
    """Give the direct reply another ID."""
    subject.later(replies=True)[0]["id"] = WRONG_ID


def extra_notification(subject: Subject) -> None:
    """Add a second notification."""
    notice = subject.later(replies=False)[0]
    subject.report["frames"].append(copy.deepcopy(notice))


def wrong_notification_id(subject: Subject) -> None:
    """Give the notification another ID."""
    subject.later(replies=False)[0]["id"] = WRONG_ID


def wrong_name(subject: Subject) -> None:
    """Give the notification another name."""
    notice = subject.later(replies=False)[0]
    next(f for f in notice["fields"] if f["id"] == 102)["hex"] = WRONG_HEX


def swapped_order(subject: Subject) -> None:
    """Put the direct reply before the notification."""
    frames = subject.report["frames"]
    notice = subject.later(replies=False)[0]
    index = frames.index(notice)
    frames[index], frames[index + 1] = frames[index + 1], frames[index]


COLLISION: Chain = [
    ("status", "Incomplete ID observation", incomplete),
    ("bootstrap", "ID bootstrap namespaces differ", bad_bootstrap),
    ("flags", "Native emitted flags differ", native_flags),
    ("reply count", "Direct reply count differs", extra_reply),
    ("reply correlation", "Direct reply correlation differs", wrong_reply_id),
    ("notification count", "Notification count differs", extra_notification),
    ("notification ID", "Notification ID allocation differs", wrong_notification_id),
    ("settings", "Collision/notification settings differ", wrong_name),
    ("ordering", "Notification/reply ordering differs", swapped_order),
]


class CollisionOrderTests:
    """Keep the checks of a collision case in the order in which they have run."""

    def test_the_unbroken_case_passes(self) -> None:
        """The retained case is accepted, so each break is the cause."""
        assert Subject("pipelined-id-collision-last-type").check()["reply_ids"], (
            "the retained case is refused"
        )

    @pytest.mark.parametrize("first", range(len(COLLISION)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("pipelined-id-collision-last-type", COLLISION, first)
        _label, message, _apply = COLLISION[first]
        with pytest.raises(ValueError, match=message):
            subject.check()


def no_error_reply(subject: Subject) -> None:
    """Remove the error reply to the unsupported request."""
    subject.report["frames"].remove(subject.later(replies=True)[0])


def wrong_error_type(subject: Subject) -> None:
    """Give the error reply the request's type."""
    subject.later(replies=True)[0]["type"] = UNSUPPORTED_TYPE


def wrong_error_text(subject: Subject) -> None:
    """Give the error reply another text."""
    reply = subject.later(replies=True)[0]
    next(f for f in reply["fields"] if f["id"] == 100)["hex"] = WRONG_HEX


def wrong_followup_id(subject: Subject) -> None:
    """Give the follow-up ACK another ID."""
    subject.later(replies=True)[1]["id"] = WRONG_ID


UNSUPPORTED: Chain = [
    ("outcomes", "Unsupported request outcomes differ", no_error_reply),
    ("envelope", "Unsupported error envelope differs", wrong_error_type),
    ("text", "Unsupported error text differs", wrong_error_text),
    ("follow-up", "Direct reply correlation differs", wrong_followup_id),
]


class UnsupportedOrderTests:
    """Keep the checks of an unsupported request in the order they have run."""

    @pytest.mark.parametrize("first", range(len(UNSUPPORTED)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("unsupported-request-type-65535", UNSUPPORTED, first)
        _label, message, _apply = UNSUPPORTED[first]
        with pytest.raises(ValueError, match=message):
            subject.check()


def extra_frame(subject: Subject) -> None:
    """Add a reply to a case that should end silently."""
    subject.report["frames"].append(copy.deepcopy(subject.report["frames"][0]))


def no_native_close(subject: Subject) -> None:
    """Report that the guest did not close the connection."""
    subject.packets["main"]["guest_server_initiated_close"] = False


CLOSE: Chain = [
    ("unnumbered close", "Missing unnumbered close", extra_frame),
    ("native close", "Missing native reply-size close", no_native_close),
]


class CloseOrderTests:
    """Keep the checks of a closing case in the order in which they have run."""

    @pytest.mark.parametrize("first", range(len(CLOSE)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("reply-255-zero-size-rejection", CLOSE, first)
        _label, message, _apply = CLOSE[first]
        with pytest.raises(ValueError, match=message):
            subject.check()
