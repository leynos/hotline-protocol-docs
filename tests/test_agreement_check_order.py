"""Pin the order of the agreement verifier's overflow and file checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before the verifier was split into ``verify_native_agreement_*`` modules
(commit 0b34126).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from native_agreement_cases import TEXT, phase
from verify_native_agreements import check_overflow, native_file

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-agreement-01"
)
PHASE = "nontext-field-over-limit"
WRONG_HEX = "ff"
ACCESS_FIELD = 110
VERSION_FIELD = 160
USER_FIELD = 103
ERROR_FIELD = 100
NOTICE_FIELD = 101
USER_LEFT = 302
USER_UPDATE = 301
ONLINE_ID = 91
FIRST_REPLAYED_ID = 2
FIRST_VIEW_ID = 10
NEXT_UID = "ffff"


class Subject:
    """One retained overflow case, ready to be broken."""

    def __init__(self, label: str) -> None:
        """Load the report and the expectation of ``label``."""
        self.label = label
        self.report: Report = json.loads(
            (BATCH / "captures" / label / "report.json").read_text()
        )
        self.expected: Report = phase(PHASE)[label][1]

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

    @staticmethod
    def field(frame: Report, identifier: int) -> Report:
        """Find one field of a frame.

        Returns
        -------
        dict[str, typing.Any]
            The field record.
        """
        return next(f for f in frame["fields"] if f["id"] == identifier)

    def check(self) -> Report:
        """Check the case.

        Returns
        -------
        dict[str, typing.Any]
            The outcome of the check.
        """
        return check_overflow(self.report, self.expected)


type Break = cabc.Callable[[Subject], None]
type Chain = list[tuple[str, str, Break]]


def broken(label: str, chain: Chain, first: int) -> Subject:
    """Break the case from check ``first`` on, last break first.

    Returns
    -------
    Subject
        The broken case.
    """
    subject = Subject(label)
    for _label, _message, apply in reversed(chain[first:]):
        apply(subject)
    return subject


def lost_frame(subject: Subject) -> None:
    """Remove the subject's last frame."""
    frames = subject.report["frames"]
    last = max(i for i, f in enumerate(frames) if f["connection"] == "subject")
    del frames[last]


def wrong_ack(subject: Subject) -> None:
    """Give the subject's login ACK another reported version."""
    ack = subject.frames("subject", 0)[0]
    subject.field(ack, VERSION_FIELD)["hex"] = WRONG_HEX


def wrong_account(subject: Subject) -> None:
    """Change the access bitmap that the observer received."""
    ack = subject.frames("observer", 354)[0]
    subject.field(ack, ACCESS_FIELD)["hex"] = WRONG_HEX


def empty_view(subject: Subject) -> None:
    """Empty the observer's last roster."""
    last = max(
        f["id"]
        for f in subject.frames("observer", 0)
        if f["is_reply"] and f["id"] >= FIRST_VIEW_ID
    )
    subject.reply("observer", last)["fields"] = []


def extra_departure(subject: Subject) -> None:
    """Give the observer a second departure notice."""
    frames = subject.report["frames"]
    notice = subject.frames("observer", USER_LEFT)[0]
    frames.append(dict(notice))


def wrong_privileges(subject: Subject) -> None:
    """Change the subject's access bitmap."""
    notice = subject.frames("subject", 354)[0]
    subject.field(notice, ACCESS_FIELD)["hex"] = WRONG_HEX


def online_fields(subject: Subject) -> None:
    """Give the subject's online liveness reply a field."""
    subject.reply("subject", ONLINE_ID)["fields"] = [
        {"id": NOTICE_FIELD, "hex": WRONG_HEX}
    ]


def other_replay(subject: Subject) -> None:
    """Change the text of the subject's first replay refusal."""
    refusal = subject.reply("subject", FIRST_REPLAYED_ID)
    subject.field(refusal, ERROR_FIELD)["hex"] = WRONG_HEX


def other_update_uid(subject: Subject) -> None:
    """Change the user ID in the observer's update notice."""
    notice = subject.frames("observer", USER_UPDATE)[0]
    subject.field(notice, USER_FIELD)["hex"] = NEXT_UID


EARLY: Chain = [
    ("shape", "partial login sequence differs", lost_frame),
    ("ack", "Overflow login ACK differs", wrong_ack),
    ("account", "independent bypass account", wrong_account),
    ("views", "Overflow visibility differs", empty_view),
    ("notifications", "Overflow notifications differ", extra_departure),
    ("privileges", "Overflow early privileges differ", wrong_privileges),
    ("online", "Overflow online request500 failed", online_fields),
    ("replay", "Overflow online replay differs", other_replay),
    ("uid", "Overflow UID changed", other_update_uid),
]


class EarlyOverflowTests:
    """Keep the early overflow checks in the order in which they have run."""

    def test_the_retained_case_is_accepted(self) -> None:
        """The retained case passes every check."""
        assert Subject(f"{PHASE}-early").check()["early"] is True, "not accepted"

    @pytest.mark.parametrize("first", range(len(EARLY)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken(f"{PHASE}-early", EARLY, first)
        _label, message, _apply = EARLY[first]
        with pytest.raises(ValueError, match=message):
            subject.check()

    def test_another_identity_is_reported_after_the_uid(self) -> None:
        """A departure for another user fails the identity check, not the UID one."""
        subject = Subject(f"{PHASE}-early")
        for kind in (USER_LEFT, USER_UPDATE):
            subject.field(subject.frames("observer", kind)[0], USER_FIELD)["hex"] = (
                NEXT_UID
            )
        with pytest.raises(ValueError, match="Overflow identity differs"):
            subject.check()


def visible_departure(subject: Subject) -> None:
    """Make the departure notice name the observer, who is on the roster."""
    view = subject.reply("observer", FIRST_VIEW_ID)["fields"][0]["hex"]
    notice = subject.frames("observer", USER_LEFT)[0]
    subject.field(notice, USER_FIELD)["hex"] = view[:4]


def no_end_of_stream(subject: Subject) -> None:
    """Remove the subject's end of stream from the events."""
    subject.report["events"] = [
        e
        for e in subject.report["events"]
        if not (e["event"] == "eof" and e["connection"] == "subject")
    ]


DELAYED: Chain = [
    ("shape", "partial login sequence differs", lost_frame),
    ("ack", "Overflow login ACK differs", wrong_ack),
    ("account", "independent bypass account", wrong_account),
    ("views", "Overflow visibility differs", empty_view),
    ("notifications", "Overflow notifications differ", extra_departure),
    ("visible", "Delayed overflow became roster-visible", visible_departure),
    ("eof", "Delayed overflow trigger did not reach EOF", no_end_of_stream),
]


class DelayedOverflowTests:
    """Keep the delayed overflow checks in the order in which they have run."""

    def test_the_retained_case_is_accepted(self) -> None:
        """The retained case passes every check."""
        assert Subject(f"{PHASE}-delayed").check()["early"] is False, "not accepted"

    @pytest.mark.parametrize("first", range(len(DELAYED)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken(f"{PHASE}-delayed", DELAYED, first)
        _label, message, _apply = DELAYED[first]
        with pytest.raises(ValueError, match=message):
            subject.check()


class FileOrderTests:
    """Keep the native agreement file checks in the order in which they have run."""

    STAGED = "native-text-staged"

    def stage(self, tmp_path: Path) -> tuple[Report, Path]:
        """Copy the staged extraction, and load its record.

        Returns
        -------
        tuple[dict, pathlib.Path]
            The extraction, and the directory it was copied to.
        """
        for source in (BATCH / self.STAGED).iterdir():
            (tmp_path / source.name).write_bytes(source.read_bytes())
        extraction = json.loads((tmp_path / "extraction.json").read_text())
        return extraction, tmp_path

    def refuse(self, tmp_path: Path, extraction: Report, kind: bytes) -> None:
        """Write ``extraction`` and run the file check expecting TEXT data."""
        (tmp_path / "extraction.json").write_text(json.dumps(extraction))
        native_file(tmp_path, kind, TEXT)

    def test_the_staged_file_is_accepted(self, tmp_path: Path) -> None:
        """The retained extraction passes with its own type and data."""
        extraction, root = self.stage(tmp_path)
        self.refuse(root, extraction, b"TEXT")

    def test_the_checks_run_in_the_order_of_the_record(self, tmp_path: Path) -> None:
        """Each fault is reported once the faults before it are mended."""
        extraction, root = self.stage(tmp_path)
        record = next(
            r for r in extraction["records"] if r["path"] == "/Hotline19/Agreement.txt"
        )
        record["path"] = "/Hotline19/Other.txt"
        with pytest.raises(ValueError, match="Missing/duplicate positive native"):
            self.refuse(root, extraction, b"BMP ")
        record["path"] = "/Hotline19/Agreement.txt"
        record["directory"] = True
        with pytest.raises(ValueError, match="found directory"):
            self.refuse(root, extraction, b"BMP ")
        record["directory"] = False
        record["attributes"]["data"]["exit_code"] = 1
        with pytest.raises(ValueError, match="Native fork read failed"):
            self.refuse(root, extraction, b"BMP ")
        record["attributes"]["data"]["exit_code"] = 0
        (root / (record["key"] + ".data")).write_bytes(TEXT + b"!")
        with pytest.raises(ValueError, match="Native agreement bytes differ"):
            self.refuse(root, extraction, b"BMP ")
        (root / (record["key"] + ".data")).write_bytes(TEXT)
        with pytest.raises(ValueError, match="Native Finder type differs"):
            self.refuse(root, extraction, b"BMP ")
