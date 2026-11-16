"""Pin the order of the HTXF verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before ``check_case`` was split into ``verify_native_htxf_checks`` and
``verify_native_htxf_events`` (commit 8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_htxf import check_case, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-htxf-01"
)
STRAY_ACTION = 100_000  # after every action of the retained cases
SHORTENED_NS = 1_000_000_000
WRONG_LOGIN_HEX = "00" * 11  # the same width as the observer's complemented login


class Subject:
    """One retained case, its packet facts and the means to break them."""

    def __init__(self, name: str) -> None:
        """Load the report and the packet reconciliation of ``name``."""
        self.name = name
        self.report: Report = json.loads(
            (BATCH / "transcripts" / name / "report.json").read_text()
        )
        reconciliation = json.loads((BATCH / "packet-reconciliation.json").read_text())
        self.packets: Report = reconciliation[name]

    def stream(self, connection: str) -> Report:
        """Find the recorded bytes of one connection.

        Returns
        -------
        dict[str, typing.Any]
            The sent and received hexadecimal strings.
        """
        return self.report["streams"][connection]

    def reply(self, connection: str, identifier: int) -> Report:
        """Find the reply frame with ``identifier`` that ``connection`` received.

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

    def event(self, connection: str, kind: str) -> Report:
        """Find the first event of ``kind`` on ``connection``.

        Returns
        -------
        dict[str, typing.Any]
            The event.
        """
        return next(
            e
            for e in self.report["events"]
            if e["connection"] == connection and e["event"] == kind
        )

    def check(self) -> Report:
        """Check the subject as the corpus check does.

        Returns
        -------
        dict[str, typing.Any]
            The result of ``check_case``.
        """
        return check_case(self.name, self.report, self.packets)


type Break = cabc.Callable[[Subject], None]


def incomplete(subject: Subject) -> None:
    """Mark the capture as failed."""
    subject.report["status"] = "failed"


def drop_ack(subject: Subject) -> None:
    """Remove the owner's ACK to request 10."""
    subject.report["frames"].remove(subject.reply("a", 10))


def short_reference(subject: Subject) -> None:
    """Give the ACK a three-byte reference."""
    next(f for f in subject.reply("a", 10)["fields"] if f["id"] == 107)["hex"] = (
        "000001"
    )


def even_reference(subject: Subject) -> None:
    """Give the banner download an even reference, which is an upload's."""
    next(f for f in subject.reply("a", 10)["fields"] if f["id"] == 107)["hex"] = (
        "00000002"
    )


def wrong_privileges(subject: Subject) -> None:
    """Give the observer the privileges of an administrator."""
    frame = next(
        f
        for f in subject.report["frames"]
        if f["connection"] == "b" and f["type"] == 354
    )
    frame["fields"][0]["hex"] = "ff" * 8


def wrong_identity(subject: Subject) -> None:
    """Make the observer log in as another account."""
    stream = subject.stream("b")
    login = bytes(v ^ 255 for v in b"fixture-low").hex()
    stream["sent_hex"] = stream["sent_hex"].replace(login, WRONG_LOGIN_HEX)


def wrong_header(subject: Subject) -> None:
    """Record a first connection whose header has no reference."""
    subject.stream("first")["sent_hex"] = "00" * 16


def long_suffix(subject: Subject) -> None:
    """Record input after the header on the first connection."""
    subject.stream("first")["sent_hex"] += "00"


def wrong_banner(subject: Subject) -> None:
    """Record other bytes than the banner on the first connection."""
    subject.stream("first")["received_hex"] = "00"


def duplicate_delivery(subject: Subject) -> None:
    """Record bytes on the duplicate connection."""
    subject.stream("second")["received_hex"] = "00"


def no_first_quiet(subject: Subject) -> None:
    """Remove the first connection's quiet observations."""
    subject.report["events"] = [
        e
        for e in subject.report["events"]
        if not (e["connection"] == "first" and e["event"] == "quiet")
    ]


def no_native_close(subject: Subject) -> None:
    """Report that the guest did not close the duplicate connection."""
    subject.packets["second"]["guest_server_initiated_close"] = False


def short_quiet(subject: Subject) -> None:
    """Shorten every quiet observation by a second."""
    for event in subject.report["events"]:
        if event["event"] == "quiet":
            event["elapsed_ns"] -= SHORTENED_NS


def first_closed_natively(subject: Subject) -> None:
    """Report that the guest closed the first connection."""
    subject.packets["first"]["guest_server_initiated_close"] = True


def late_owner_close(subject: Subject) -> None:
    """Move the owner's close after the duplicate's end of stream."""
    subject.event("a", "close")["action"] = STRAY_ACTION


# Each entry names the check that its break trips, in the order of the checks.
DUPLICATE_BREAKS: list[tuple[str, str, Break]] = [
    ("status", "Incomplete HTXF observation", incomplete),
    ("missing ACK", "Missing HTXF success ACK", drop_ack),
    ("reference width", "HTXF reference width differs", short_reference),
    ("reference parity", "Reference parity differs", even_reference),
    ("observer privileges", "Observer privileges differ", wrong_privileges),
    ("observer identity", "Observer identity differs", wrong_identity),
    (
        "header",
        "banner-duplicate-after-send: physical HTXF header differs",
        wrong_header,
    ),
    ("suffix", "Unexpected HTXF input suffix", long_suffix),
    ("banner", "Banner bytes differ", wrong_banner),
    ("quiet observation", "Missing HTXF quiet/close observation", no_first_quiet),
    (
        "duplicate delivery",
        "Rejected/duplicate connection delivered bytes",
        duplicate_delivery,
    ),
    ("native close", "Missing native close", no_native_close),
    ("short quiet", "Short HTXF quiet observation", short_quiet),
    (
        "first closed",
        "First duplicate transport closed natively",
        first_closed_natively,
    ),
    ("ordering", "Duplicate cleanup ordering differs", late_owner_close),
]


def broken(name: str, breaks: list[tuple[str, str, Break]], first: int) -> Subject:
    """Break the case from check ``first`` on, last break first.

    The breaks are applied last to first, so that the removal of the ACK comes
    after the breaks that edit it.

    Returns
    -------
    Subject
        The broken case.
    """
    subject = Subject(name)
    for _label, _message, apply in reversed(breaks[first:]):
        apply(subject)
    return subject


class DuplicateCaseOrderTests:
    """Keep the checks of a banner case in the order in which they have always run."""

    def test_the_unbroken_case_passes(self) -> None:
        """The retained case is accepted, so each break is the cause."""
        assert Subject("banner-duplicate-after-send").check()["case"], (
            "the retained case is refused"
        )

    @pytest.mark.parametrize("first", range(len(DUPLICATE_BREAKS)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("banner-duplicate-after-send", DUPLICATE_BREAKS, first)
        _label, message, _apply = DUPLICATE_BREAKS[first]
        with pytest.raises(ValueError, match=message):
            subject.check()


def wrong_preflight_size(subject: Subject) -> None:
    """Advertise another size for the preflight banner."""
    next(f for f in subject.reply("main", 10)["fields"] if f["id"] == 108)["hex"] = (
        "00000001"
    )


def preflight_reference(subject: Subject) -> None:
    """Give the preflight ACK a three-byte reference."""
    next(f for f in subject.reply("main", 10)["fields"] if f["id"] == 107)["hex"] = (
        "000001"
    )


PREFLIGHT_BREAKS: list[tuple[str, str, Break]] = [
    ("reference width", "HTXF reference width differs", preflight_reference),
    ("size", "Preflight size differs", wrong_preflight_size),
]


class PreflightOrderTests:
    """Keep the preflight checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(PREFLIGHT_BREAKS)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("preflight", PREFLIGHT_BREAKS, first)
        _label, message, _apply = PREFLIGHT_BREAKS[first]
        with pytest.raises(ValueError, match=message):
            subject.check()


def wrong_upload_header(subject: Subject) -> None:
    """Record an upload connection whose header has no reference."""
    subject.stream("upload")["sent_hex"] = "00" * 16


def wrong_upload_body(subject: Subject) -> None:
    """Record an upload whose body is cut short."""
    stream = subject.stream("upload")
    stream["sent_hex"] = stream["sent_hex"][:-2]


def no_upload_close(subject: Subject) -> None:
    """Remove the upload connection's end of stream."""
    subject.report["events"] = [
        e
        for e in subject.report["events"]
        if not (e["connection"] == "upload" and e["event"] == "eof")
    ]


def no_lookup_ack(subject: Subject) -> None:
    """Remove the reply to the lookup after the upload."""
    subject.report["frames"].remove(subject.reply("a", 11))


UPLOAD_BREAKS: list[tuple[str, str, Break]] = [
    (
        "header",
        "upload-nonfolder-selector-0: physical HTXF header differs",
        wrong_upload_header,
    ),
    ("body", "Upload stream differs", wrong_upload_body),
    ("close", "Missing upload close", no_upload_close),
    ("lookup", "Missing HTXF success ACK", no_lookup_ack),
]


class UploadCaseOrderTests:
    """Keep the checks of an upload case in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(UPLOAD_BREAKS)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = broken("upload-nonfolder-selector-0", UPLOAD_BREAKS, first)
        _label, message, _apply = UPLOAD_BREAKS[first]
        with pytest.raises(ValueError, match=message):
            subject.check()


class CorpusOrderTests:
    """Keep the corpus-level checks in the order in which they have always run."""

    @staticmethod
    def copy_corpus(tmp_path: Path) -> Path:
        """Copy the retained corpus so that it can be broken.

        Returns
        -------
        pathlib.Path
            The copy.
        """
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        return directory

    @staticmethod
    def edit_manifest(directory: Path, **changes: object) -> None:
        """Replace keys of the manifest."""
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest.update(changes)
        path.write_text(json.dumps(manifest))

    def test_the_case_inventory_precedes_the_oracle_identity(
        self, tmp_path: Path
    ) -> None:
        """A wrong case list is reported although the oracle hash is wrong."""
        directory = self.copy_corpus(tmp_path)
        self.edit_manifest(directory, cases=[], oracle_sha256="0" * 64)
        with pytest.raises(ValueError, match="HTXF case inventory differs"):
            verify(directory)

    def test_the_oracle_identity_precedes_the_packet_reads(
        self, tmp_path: Path
    ) -> None:
        """A wrong oracle hash is reported although the host capture is missing."""
        directory = self.copy_corpus(tmp_path)
        self.edit_manifest(directory, oracle_sha256="0" * 64)
        (directory / "host.pcap").unlink()
        with pytest.raises(ValueError, match="HTXF oracle identity differs"):
            verify(directory)

    def test_the_packet_reads_precede_the_cases(self, tmp_path: Path) -> None:
        """A missing host capture is reported before any case is read."""
        directory = self.copy_corpus(tmp_path)
        (directory / "host.pcap").unlink()
        shutil.rmtree(directory / "transcripts")
        with pytest.raises(FileNotFoundError):
            verify(directory)

    def test_the_reconciliation_precedes_the_native_uploads(
        self, tmp_path: Path
    ) -> None:
        """A changed reconciliation is reported although a native upload differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "packet-reconciliation.json").write_text("{}")
        (directory / "native-uploads/catalog-11282.data").write_bytes(b"wrong")
        with pytest.raises(ValueError, match="Retained packet reconciliation differs"):
            verify(directory)
