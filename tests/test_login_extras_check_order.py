"""Pin the order of the login-extras verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before the verifier was split into ``verify_native_login_extras_*`` modules
(commit 8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import typing as typ
from pathlib import Path

import pytest
from native_login_extras_cases import configured
from verify_native_login_extras import (
    check_configured,
    check_downloads,
    check_lifetime,
)

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-login-extras-01"
)
WRONG_HEX = "ff"
WRONG_ERROR = 1
LOGIN_ACK = 0
AGREEMENT = 109
PRIVILEGES = 354
BANNER = 122
NOTICE_FIELD = 101
ACCESS_FIELD = 110
BANNER_TYPE_FIELD = 152
SERVER_NAME_FIELD = 162
UNNAMED_FIELD = 161
VERSION_FIELD = 160
LIVENESS_ID = 90
SIZE_FIELD = 108
REFERENCE_FIELD = 107
ZERO_REFERENCE = "00000000"


class Subject:
    """One retained login-extras case, ready to be broken."""

    def __init__(self, name: str) -> None:
        """Load the report and the original agreement."""
        self.report: Report = json.loads(
            (BATCH / "captures" / name / "report.json").read_text()
        )
        raw = (BATCH / "original-agreement.data").read_bytes()
        self.agreement = raw.replace(b"\r\n", b"\r")

    def frames(self, connection: str | None, kind: int) -> list[Report]:
        """List the frames of ``kind``, optionally of one connection.

        Returns
        -------
        list[dict[str, typing.Any]]
            The matching frames.
        """
        return [
            f
            for f in self.report["frames"]
            if f["type"] == kind
            and (connection is None or f["connection"] == connection)
        ]

    def reply(self, identifier: int, connection: str = "main") -> Report:
        """Find the reply with ``identifier``.

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


def lost_frame(subject: Subject) -> None:
    """Remove the last frame of the case."""
    subject.report["frames"].pop()


def wrong_extras(subject: Subject) -> None:
    """Give the login ACK another reported version."""
    ack = subject.report["frames"][0]
    subject.field(ack, VERSION_FIELD)["hex"] = WRONG_HEX


def other_reply_ids(subject: Subject) -> None:
    """Give the acceptance ACK another ID."""
    subject.reply(2)["id"] = 3


def wrong_agreement(subject: Subject) -> None:
    """Change the agreement text."""
    subject.field(subject.frames("main", AGREEMENT)[0], NOTICE_FIELD)["hex"] = WRONG_HEX


def wrong_privileges(subject: Subject) -> None:
    """Change the access mask."""
    subject.field(subject.frames("main", PRIVILEGES)[0], ACCESS_FIELD)["hex"] = (
        WRONG_HEX
    )


def wrong_banner(subject: Subject) -> None:
    """Change the banner type."""
    subject.field(subject.frames("main", BANNER)[0], BANNER_TYPE_FIELD)["hex"] = (
        WRONG_HEX
    )


def liveness_fields(subject: Subject) -> None:
    """Give the liveness ACK a field."""
    subject.reply(90)["fields"] = [{"id": UNNAMED_FIELD, "hex": WRONG_HEX}]


def accept_fields(subject: Subject) -> None:
    """Give the acceptance ACK a field."""
    subject.reply(2)["fields"] = [{"id": UNNAMED_FIELD, "hex": WRONG_HEX}]


CONFIGURED: Chain = [
    ("shape", "Configured login/banner sequence differs", lost_frame),
    ("extras", "Configured login-extra values differ", wrong_extras),
    ("reply IDs", "Configured reply IDs differ", other_reply_ids),
    ("agreement", "Configured agreement changed", wrong_agreement),
    ("privileges", "Configured privileges changed", wrong_privileges),
    ("banner", "Configured banner metadata differs", wrong_banner),
    ("liveness", "Configured liveness ACK differs", liveness_fields),
    (
        "acceptance",
        "Acceptance ACK unexpectedly refreshes login extras",
        accept_fields,
    ),
]


class ConfiguredOrderTests:
    """Keep the configured-login checks in the order in which they have run."""

    @staticmethod
    def expected() -> Report:
        """Plan the case that the retained report was recorded for.

        Returns
        -------
        dict[str, typing.Any]
            The case's expectation.
        """
        return configured("url")["url-190-delayed"][1]

    @pytest.mark.parametrize("first", range(len(CONFIGURED)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("url-190-delayed", CONFIGURED, first)
        _label, message, _apply = CONFIGURED[first]
        with pytest.raises(ValueError, match=message):
            check_configured(subject.report, self.expected(), subject.agreement)


def waiting_extra_frame(subject: Subject) -> None:
    """Give the waiting session one more frame at the end."""
    subject.report["frames"].append({
        "connection": "waiting",
        "type": 0,
        "is_reply": 0,
        "id": 0,
        "error": 0,
        "fields": [],
    })


def observer_wrong_extras(subject: Subject) -> None:
    """Give the observer's login ACK another reported version."""
    ack = subject.frames("observer", LOGIN_ACK)[0]
    subject.field(ack, VERSION_FIELD)["hex"] = WRONG_HEX


def observer_wrong_agreement(subject: Subject) -> None:
    """Change the observer's agreement text."""
    subject.field(subject.frames("observer", AGREEMENT)[0], NOTICE_FIELD)["hex"] = (
        WRONG_HEX
    )


def observer_refreshed(subject: Subject) -> None:
    """Give the observer's liveness ACK a refreshed server name."""
    subject.reply(LIVENESS_ID, "observer")["fields"] = [
        {"id": SERVER_NAME_FIELD, "hex": WRONG_HEX}
    ]


def with_field(identifier: int, connection: str, field: int) -> Break:
    """Build a break that gives one reply a field that is not a login extra.

    Returns
    -------
    collections.abc.Callable[[Subject], None]
        The break.
    """

    def apply(subject: Subject) -> None:
        """Give the reply a field."""
        subject.reply(identifier, connection)["fields"] = [
            {"id": field, "hex": WRONG_HEX}
        ]

    return apply


def waiting_wrong_banner(subject: Subject) -> None:
    """Change the banner type of the waiting session."""
    subject.field(subject.frames("waiting", BANNER)[0], BANNER_TYPE_FIELD)["hex"] = (
        WRONG_HEX
    )


LIFETIME: Chain = [
    ("observer extras", "Configured login-extra values differ", observer_wrong_extras),
    ("agreement", "Lifetime agreement changed", observer_wrong_agreement),
    ("refresh", "Existing-session login extras were refreshed", observer_refreshed),
    (
        "acceptance",
        "Waiting acceptance refreshed its login extras",
        with_field(2, "waiting", NOTICE_FIELD),
    ),
    (
        "waiting liveness",
        "Waiting session failed to complete after the change",
        with_field(LIVENESS_ID, "waiting", NOTICE_FIELD),
    ),
    (
        "observer liveness",
        "Existing online session lost liveness",
        with_field(91, "observer", NOTICE_FIELD),
    ),
    ("completion", "Waiting name-change completion differs", waiting_extra_frame),
    ("banner", "Name-only save changed banner metadata", waiting_wrong_banner),
]


class LifetimeOrderTests:
    """Keep the lifetime checks in the order in which they have run."""

    @pytest.mark.parametrize("first", range(len(LIFETIME)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("name-change-with-existing-sessions", LIFETIME, first)
        _label, message, _apply = LIFETIME[first]
        with pytest.raises(ValueError, match=message):
            check_lifetime(subject.report, subject.agreement)


def wrong_login_ack(subject: Subject) -> None:
    """Give the login ACK another reported version."""
    ack = subject.frames("main", LOGIN_ACK)[0]
    subject.field(ack, VERSION_FIELD)["hex"] = WRONG_HEX


def wrong_bootstrap(subject: Subject) -> None:
    """Change the agreement text of the login bootstrap."""
    subject.field(subject.frames("main", AGREEMENT)[0], NOTICE_FIELD)["hex"] = WRONG_HEX


def failed_reply(subject: Subject) -> None:
    """Give the first banner reply an error."""
    subject.reply(10)["error"] = WRONG_ERROR


def wrong_size(identifier: int) -> Break:
    """Build a break that changes the size of one banner reference reply.

    Returns
    -------
    collections.abc.Callable[[Subject], None]
        The break.
    """

    def apply(subject: Subject) -> None:
        """Change the size field."""
        subject.field(subject.reply(identifier), SIZE_FIELD)["hex"] = WRONG_HEX

    return apply


def zero_reference(subject: Subject) -> None:
    """Give the first banner reply a reference of zero."""
    subject.field(subject.reply(10), REFERENCE_FIELD)["hex"] = ZERO_REFERENCE


def wrong_banner_bytes(subject: Subject) -> None:
    """Change the banner bytes that the first data connection received."""
    subject.report["streams"]["data10"]["received_hex"] = WRONG_HEX


def wrong_attach(subject: Subject) -> None:
    """Change the greeting that the first data connection sent."""
    subject.report["streams"]["data10"]["sent_hex"] = WRONG_HEX


DOWNLOADS: Chain = [
    ("login ACK", "Configured login-extra values differ", wrong_login_ack),
    ("bootstrap", "Banner-reference login bootstrap differs", wrong_bootstrap),
    ("replies", "Banner-reference replies differ", failed_reply),
    ("size", "Banner reference/size fields differ", wrong_size(10)),
    ("zero", "Banner reference equals zero", zero_reference),
    ("banner bytes", "Configured banner bytes changed", wrong_banner_bytes),
    ("attach", "Banner attach reference differs", wrong_attach),
]


class DownloadOrderTests:
    """Keep the banner-download checks in the order in which they have run."""

    @pytest.mark.parametrize("first", range(len(DOWNLOADS)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("login-value-versus-banner-references", DOWNLOADS, first)
        _label, message, _apply = DOWNLOADS[first]
        with pytest.raises(ValueError, match=message):
            check_downloads(subject.report, subject.agreement)

    def test_the_first_reference_is_checked_through_before_the_second(self) -> None:
        """A late fault in the first reference is reported before the second."""
        subject = Subject("login-value-versus-banner-references")
        wrong_size(11)(subject)
        wrong_attach(subject)
        with pytest.raises(ValueError, match="Banner attach reference differs"):
            check_downloads(subject.report, subject.agreement)
