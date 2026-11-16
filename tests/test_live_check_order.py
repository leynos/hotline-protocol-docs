"""Pin the order of the live-account verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before the verifier was split into ``verify_native_live_*`` modules (commit
8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from verify_native_live_accounts import check_delete, check_edit, stopped, waits

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-live-accounts-01"
)
WRONG_ERROR = 1
NO_ERROR = 0
WRONG_HEX = "ff"
ACCESS = 354
ANNOUNCE = 301
NOTICE = 104
LEFT = 302
RENAMED_HEX = b"Stored Beta27".hex()
NAME_FIELD = 102
FLAGS_FIELD = 112
SHORTENED_NS = 1_000_000_000
TRUNCATED_BYTES = 10
REMOVAL_BYTES = 28
TYPE_WORD_END = 4


class Subject:
    """One retained case, its packet facts and its unread tail, ready to break."""

    def __init__(self, name: str) -> None:
        """Load the report and the unread tail."""
        self.report: Report = json.loads((BATCH / name / "report.json").read_text())
        tails = json.loads((BATCH / "delete-unread-tails.json").read_text())
        self.tail = bytes.fromhex(tails["main"])
        self.observations: Report = {
            c: {"guest_server_initiated_close": True, "guest_server_close_kind": "FIN"}
            for c in ["one", "two"]
        }

    def frames(self, connection: str, kind: int) -> list[Report]:
        """List the frames of ``kind`` that ``connection`` received.

        Returns
        -------
        list[dict[str, typing.Any]]
            The frames, in order.
        """
        return [
            f
            for f in self.report["frames"]
            if f["connection"] == connection and f["type"] == kind
        ]

    def reply(self, connection: str, identifier: int) -> Report:
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

    def renames(self, connection: str) -> list[Report]:
        """List the rename updates that ``connection`` received.

        Returns
        -------
        list[dict[str, typing.Any]]
            The 301 frames that carry the new name.
        """
        return [
            f
            for f in self.frames(connection, ANNOUNCE)
            if any(
                x["id"] == NAME_FIELD and x["hex"] == RENAMED_HEX for x in f["fields"]
            )
        ]


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


def small_roster(subject: Subject) -> None:
    """Cut the initial roster to two rows."""
    reply = subject.reply("main", 10)
    reply["fields"] = reply["fields"][:2]


def wrong_initial_access(subject: Subject) -> None:
    """Give the first subject another initial access mask."""
    subject.frames("one", ACCESS)[0]["fields"][0]["hex"] = WRONG_HEX


def wrong_edit_ack(subject: Subject) -> None:
    """Make the edit's ACK an error."""
    subject.reply("main", 11)["error"] = WRONG_ERROR


def lost_update(subject: Subject) -> None:
    """Remove one rename update from the caller."""
    subject.report["frames"].remove(subject.renames("main")[-1])


def wrong_update_bytes(subject: Subject) -> None:
    """Give a rename update other flag bytes."""
    update = subject.renames("main")[0]
    next(f for f in update["fields"] if f["id"] == FLAGS_FIELD)["hex"] = "0000"


def late_ack(subject: Subject) -> None:
    """Move the caller's ACK after the roster notifications."""
    ack = subject.reply("main", 11)
    subject.report["frames"].remove(ack)
    subject.report["frames"].append(ack)


def late_access(subject: Subject) -> None:
    """Move the first subject's second access update to the end."""
    access = subject.frames("one", ACCESS)[1]
    subject.report["frames"].remove(access)
    subject.report["frames"].append(access)


def revocation_lost(subject: Subject) -> None:
    """Let the first subject's download succeed after the revocation."""
    subject.reply("one", 91)["error"] = NO_ERROR


def control_lost(subject: Subject) -> None:
    """Fail the second subject's liveness probe."""
    subject.reply("two", 80)["error"] = WRONG_ERROR


def no_snapshot(subject: Subject) -> None:
    """Empty the roster read after the edit."""
    subject.reply("main", 12)["fields"] = []


def wrong_flag_ack(subject: Subject) -> None:
    """Make the password-only ACK an error."""
    subject.reply("main", 21)["error"] = WRONG_ERROR


def stale_roster(subject: Subject) -> None:
    """Leave the closed subjects in the final roster."""
    subject.reply("main", 40)["fields"] = subject.reply("main", 12)["fields"]


def lost_removal(subject: Subject) -> None:
    """Remove a removal notification from the caller."""
    subject.report["frames"].remove(subject.frames("main", LEFT)[-1])


EDIT: Chain = [
    ("roster", "Live account initial roster cardinality differs", small_roster),
    ("initial access", "Initial live access differs", wrong_initial_access),
    ("ACK", "Live edit ACK differs", wrong_edit_ack),
    ("recipients", "Live rename recipients differ", lost_update),
    ("bytes", "Live rename field bytes differ", wrong_update_bytes),
    ("order", "Caller ACK/rename/roster order differs", late_ack),
    ("own access", "Own 354 must precede own rename", late_access),
    ("revocation", "Live revocation not enforced", revocation_lost),
    ("control", "Password change interrupted live control", control_lost),
    ("snapshot", "Live post-edit snapshot differs", no_snapshot),
    ("flag ACK", "Password/attribute-only ACK differs", wrong_flag_ack),
    ("final roster", "Closed live subjects remain in final edit roster", stale_roster),
    ("removals", "Live EOF removal notifications differ", lost_removal),
]


class EditOrderTests:
    """Keep the edit checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(EDIT)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("edit", EDIT, first)
        _label, message, _apply = EDIT[first]
        with pytest.raises(ValueError, match=message):
            check_edit(subject.report)


def wrong_delete_ack(subject: Subject) -> None:
    """Make the deletion ACK an error."""
    subject.reply("main", 11)["error"] = WRONG_ERROR


def wrong_notice(subject: Subject) -> None:
    """Give a deletion notice an error word."""
    subject.frames("one", NOTICE)[0]["error"] = WRONG_ERROR


def client_close(subject: Subject) -> None:
    """Report that the client closed first."""
    subject.observations["two"]["guest_server_initiated_close"] = False


def short_stale_roster(subject: Subject) -> None:
    """Cut the stale roster to one row."""
    reply = subject.reply("main", 12)
    reply["fields"] = reply["fields"][:1]


def early_removal(subject: Subject) -> None:
    """Add a removal notification to the report."""
    subject.report["frames"].append(
        subject.frames("main", ANNOUNCE)[0] | {"type": LEFT}
    )


def readable_account(subject: Subject) -> None:
    """Make the deleted account readable."""
    subject.reply("main", 14)["error"] = NO_ERROR


def cut_header(subject: Subject) -> None:
    """Cut the unread tail inside a header."""
    subject.tail = subject.tail[:TRUNCATED_BYTES]


def other_removal(subject: Subject) -> None:
    """Change the type of the first unread notification."""
    tail = subject.tail
    subject.tail = tail[:2] + b"\x00\x6f" + tail[TYPE_WORD_END:]


def one_removal(subject: Subject) -> None:
    """Keep one of the two unread removal notices."""
    subject.tail = subject.tail[:REMOVAL_BYTES]


DELETE: Chain = [
    ("roster", "Live account initial roster cardinality differs", small_roster),
    ("ACK", "Live deletion ACK differs", wrong_delete_ack),
    ("notice", "Deleted account notice differs", wrong_notice),
    ("close", "Deletion must retain native first FIN", client_close),
    ("stale roster", "Deletion stale roster observation changed", short_stale_roster),
    ("unread tail", "Deletion report must preserve unread removal tail", early_removal),
    ("lookup", "Live deleted account lookup differs", readable_account),
    ("header", "Truncated late removal header", cut_header),
    ("output", "Unexpected unread deletion output", other_removal),
    ("UIDs", "Late removal UIDs differ", one_removal),
]


class DeleteOrderTests:
    """Keep the deletion checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(DELETE)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("delete", DELETE, first)
        _label, message, _apply = DELETE[first]
        with pytest.raises(ValueError, match=message):
            check_delete(subject.report, subject.tail, subject.observations)


class WaitOrderTests:
    """Keep the wait checks in the order in which they have always run."""

    @staticmethod
    def edit_case() -> tuple[Report, list[Report]]:
        """Load the edit report and its plan.

        Returns
        -------
        tuple[dict, list]
            The report and the plan's steps.
        """
        report = json.loads((BATCH / "edit/report.json").read_text())
        plan = json.loads((BATCH / "edit/plan.json").read_text())
        return report, plan["steps"]

    def test_a_missing_wait_precedes_a_short_wait(self) -> None:
        """A wait with no event is reported before a short wait is."""
        report, steps = self.edit_case()
        quiet = [e for e in report["events"] if e["event"] == "quiet"]
        quiet[1]["elapsed_ns"] -= SHORTENED_NS
        report["events"].remove(quiet[0])
        with pytest.raises(ValueError, match="Missing live account wait event"):
            waits(report, steps)

    def test_a_short_wait_is_reported(self) -> None:
        """A wait shorter than planned is reported."""
        report, steps = self.edit_case()
        quiet = next(e for e in report["events"] if e["event"] == "quiet")
        quiet["elapsed_ns"] -= SHORTENED_NS
        with pytest.raises(ValueError, match="Short live account wait"):
            waits(report, steps)

    def test_the_status_precedes_the_packet_use(self) -> None:
        """A completed stopped witness is refused before any packet is read."""
        report = json.loads((BATCH / "stopped/report.json").read_text())
        report["status"] = "completed"
        report["events"] = []
        with pytest.raises(ValueError, match="must remain a reset failure"):
            stopped(report, [], [])
