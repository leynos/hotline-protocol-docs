"""Pin the order of the identity verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before ``deletion`` and ``duplicate`` were split into smaller functions (commit
8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from verify_native_account_identity import deletion, duplicate

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-account-identity-01"
)
WRONG_ERROR = 1
NO_ERROR = 0
MASK = "ff" * 8
ANNOUNCE = 301
PRIVILEGES = 354
NOTICE = 104


class Subject:
    """One retained deletion or duplicate case, ready to be broken."""

    def __init__(self, name: str) -> None:
        """Load the report, the packet observation and the unread tail."""
        self.report: Report = json.loads((BATCH / name / "report.json").read_text())
        observations = json.loads((BATCH / "packet-observations.json").read_text())
        self.observation: Report = observations.get(name, {})
        tails = json.loads((BATCH / "unread-tails.json").read_text())
        self.tail = bytes.fromhex(tails[name]["main"]) if name in tails else b""

    def frame(self, connection: str, identifier: int) -> Report:
        """Find the reply with ``identifier`` that ``connection`` received.

        Returns
        -------
        dict[str, typing.Any]
            The frame.
        """
        return next(
            f
            for f in self.report["frames"]
            if f["connection"] == connection and f["is_reply"] and f["id"] == identifier
        )

    def first(self, connection: str, kind: int) -> Report:
        """Find the first frame of ``kind`` that ``connection`` received.

        Returns
        -------
        dict[str, typing.Any]
            The frame.
        """
        return next(
            f
            for f in self.report["frames"]
            if f["connection"] == connection and f["type"] == kind
        )


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


def wrong_rejection(subject: Subject) -> None:
    """Make the duplicate create succeed."""
    subject.frame("main", 10)["error"] = NO_ERROR


def wrong_record(subject: Subject) -> None:
    """Make the read of the original account fail."""
    subject.frame("main", 20)["error"] = WRONG_ERROR


def lost_liveness(subject: Subject) -> None:
    """Make the liveness probe fail."""
    subject.frame("main", 90)["error"] = WRONG_ERROR


DUPLICATE: Chain = [
    ("rejection", "Duplicate create rejection differs", wrong_rejection),
    ("record", "Identity account record differs", wrong_record),
    ("liveness", "Duplicate control liveness differs", lost_liveness),
]


class DuplicateOrderTests:
    """Keep the duplicate checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(DUPLICATE)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("duplicate-exact", DUPLICATE, first)
        _label, message, _apply = DUPLICATE[first]
        with pytest.raises(ValueError, match=message):
            duplicate(subject.report, uppercase=False)


def wrong_mask(subject: Subject) -> None:
    """Give the target the wrong protection mask."""
    subject.first("target", PRIVILEGES)["fields"][0]["hex"] = MASK


def wrong_announcement(subject: Subject) -> None:
    """Give the announcement another icon."""
    announce = subject.first("main", ANNOUNCE)
    next(f for f in announce["fields"] if f["id"] == 104)["hex"] = "0000"


def kick_allowed(subject: Subject) -> None:
    """Make the kick of the protected target succeed."""
    subject.frame("main", 11)["error"] = NO_ERROR


def target_lost(subject: Subject) -> None:
    """Make the protected target's liveness probe fail."""
    subject.frame("target", 80)["error"] = WRONG_ERROR


def wrong_ack(subject: Subject) -> None:
    """Make the deletion ACK an error."""
    subject.frame("main", 12)["error"] = WRONG_ERROR


def wrong_notice(subject: Subject) -> None:
    """Give the deletion notice an error word."""
    subject.first("target", NOTICE)["error"] = WRONG_ERROR


def no_close(subject: Subject) -> None:
    """Report that the guest did not close the target's connection."""
    subject.observation["target"]["guest_server_initiated_close"] = False


def still_readable(subject: Subject) -> None:
    """Make the deleted account readable."""
    subject.frame("main", 20)["error"] = NO_ERROR


def empty_roster(subject: Subject) -> None:
    """Make the post-delete roster empty."""
    subject.frame("main", 30)["fields"] = []


def short_tail(subject: Subject) -> None:
    """Drop the unread removal notice."""
    subject.tail = b""


def wrong_removal(subject: Subject) -> None:
    """Change the type of the unread removal notice."""
    raw = bytearray(subject.tail)
    raw[3] ^= 1
    subject.tail = bytes(raw)


PROTECTED: Chain = [
    ("mask", "Protection mask differs", wrong_mask),
    ("announcement", "Owned target announcement differs", wrong_announcement),
    ("kick", "Kick protection rejection differs", kick_allowed),
    ("liveness", "Protected subject lost liveness", target_lost),
    ("ACK", "Deletion ACK differs", wrong_ack),
    ("notice", "Deletion notice differs", wrong_notice),
    ("close", "Protected/self-delete guest close differs", no_close),
    (
        "lookup",
        "Deleted account still readable or wrong lookup failure",
        still_readable,
    ),
    ("roster", "Bounded post-delete stale roster differs", empty_roster),
    ("tail size", "Unread target removal size differs", short_tail),
    ("removal", "Unread target removal identity differs", wrong_removal),
]


def swap_ack_and_notice(subject: Subject) -> None:
    """Put the self-deletion notice before the ACK."""
    frames = subject.report["frames"]
    ack = subject.frame("target", 12)
    notice = subject.first("target", NOTICE)
    first, second = frames.index(ack), frames.index(notice)
    frames[first], frames[second] = frames[second], frames[first]


SELF: Chain = [
    ("notice", "Deletion notice differs", wrong_notice),
    ("order", "Self-delete notice precedes ACK", swap_ack_and_notice),
    ("close", "Protected/self-delete guest close differs", no_close),
]


class DeletionOrderTests:
    """Keep the deletion checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(PROTECTED)))
    def test_a_protected_deletion_reports_the_first_broken_check(
        self, first: int
    ) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("protected", PROTECTED, first)
        _label, message, _apply = PROTECTED[first]
        with pytest.raises(ValueError, match=message):
            deletion(subject.report, "protected", subject.observation, subject.tail)

    @pytest.mark.parametrize("first", range(len(SELF)))
    def test_a_self_deletion_reports_the_first_broken_check(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("self", SELF, first)
        _label, message, _apply = SELF[first]
        with pytest.raises(ValueError, match=message):
            deletion(subject.report, "self", subject.observation, subject.tail)
