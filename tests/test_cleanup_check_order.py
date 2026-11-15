"""Pin the order of the cleanup verifier's checks.

The goldens observe only the retained corpus, so the order in which an unsound
case is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before they were split into ``verify_native_cleanup_checks`` and
``verify_native_cleanup_timing`` (commit 8b4c3df).

A case that breaks check ``n`` also breaks every check after it, so the message
that comes back names the first check that the verifier makes.
"""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from pcap_tcp import read_packets
from verify_native_cleanup import check_download, check_upload, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-cleanup-01"
)
PARTIAL_PREFIX = 1024
FLIPPED_OFFSET = 50  # inside the truncated stream, so both breaks coexist
TRUNCATED_BYTES = 100  # shorter than the prefix that a partial case must reach
WRONG_SIZE = "00000001"
EVEN_REFERENCE = "00000002"
NONZERO_ACK = "0001"
NOT_A_DEPARTURE = "012d"  # the type word of a 301, not a 302
STRAY_ACTION = 100_000  # after every action of the retained cases


def load(case: str) -> Report:
    """Load the report of one retained case.

    Returns
    -------
    dict[str, typing.Any]
        The parsed report.
    """
    return json.loads((BATCH / "transcripts" / case / "report.json").read_text())


def frame(report: Report, identifier: int) -> Report:
    """Find the reply frame of the owner ``a`` with ``identifier``.

    Returns
    -------
    dict[str, typing.Any]
        The frame.
    """
    return next(
        f
        for f in report["frames"]
        if f["connection"] == "a" and f["is_reply"] == 1 and f["id"] == identifier
    )


def set_field(reply: Report, field_id: int, value: str) -> None:
    """Replace the hexadecimal value of one field of a reply."""
    next(f for f in reply["fields"] if f["id"] == field_id)["hex"] = value


class Subject:
    """One report and the packet facts that a check reads, ready to be broken."""

    def __init__(self, case: str) -> None:
        """Load the case, the baseline and the close observations."""
        self.report = load(case)
        self.baseline = bytes.fromhex(
            load("cleanup-baseline")["streams"]["reference"]["received_hex"]
        )
        closed = {"guest_server_initiated_close": True}
        self.packets = {
            "reference": dict(closed),
            "stale": dict(closed),
            "upload": dict(closed),
        }

    def stream(self, name: str) -> Report:
        """Find the recorded bytes of one connection.

        Returns
        -------
        dict[str, typing.Any]
            The sent and received hexadecimal strings.
        """
        return self.report["streams"][name]


type Break = cabc.Callable[[Subject], None]


def drop_reply(subject: Subject) -> None:
    """Remove the reply to request 10."""
    subject.report["frames"].remove(frame(subject.report, 10))


def odd_to_even(subject: Subject) -> None:
    """Give the download an even reference, which is an upload's."""
    set_field(frame(subject.report, 10), 107, EVEN_REFERENCE)


def wrong_advertised(subject: Subject) -> None:
    """Advertise a size other than the baseline's."""
    set_field(frame(subject.report, 10), 108, WRONG_SIZE)


def wrong_logical(subject: Subject) -> None:
    """Report a logical size other than the forks'."""
    set_field(frame(subject.report, 10), 207, WRONG_SIZE)


def wrong_greeting(subject: Subject) -> None:
    """Record a greeting that does not carry the reference."""
    subject.stream("reference")["sent_hex"] = "00"


def flip_received(subject: Subject) -> None:
    """Flip one byte of the received stream."""
    stream = subject.stream("reference")
    raw = bytearray.fromhex(stream["received_hex"])
    raw[FLIPPED_OFFSET] ^= 1
    stream["received_hex"] = raw.hex()


def truncate_received(subject: Subject) -> None:
    """Cut the received stream short of the prefix a partial case must reach."""
    stream = subject.stream("reference")
    stream["received_hex"] = stream["received_hex"][: TRUNCATED_BYTES * 2]


def wrong_owner_ack(subject: Subject) -> None:
    """Make the owner's cleanup ACK carry a payload."""
    frame(subject.report, 21)["payload_hex"] = NONZERO_ACK


def wrong_duplicate_ack(subject: Subject) -> None:
    """Make the duplicate cleanup ACK carry a payload."""
    frame(subject.report, 22)["payload_hex"] = NONZERO_ACK


def no_native_close(subject: Subject) -> None:
    """Report that the guest did not close the data connection."""
    subject.packets["reference"]["guest_server_initiated_close"] = False


def stale_delivers(subject: Subject) -> None:
    """Let the removed reference receive bytes."""
    subject.stream("stale")["received_hex"] = "00"


def wrong_stale_greeting(subject: Subject) -> None:
    """Record a stale greeting that does not carry the reference."""
    subject.stream("stale")["sent_hex"] = "00"


def extra_read(subject: Subject) -> None:
    """Add a read after the owner's ACK that the ordering does not allow."""
    subject.report["events"].append({
        "action": STRAY_ACTION,
        "connection": "reference",
        "event": "receive",
        "elapsed_ns": 0,
        "hex": "00",
    })


# Each entry names the check that its break trips, in the order of the checks.
DOWNLOAD_BREAKS: list[tuple[str, str, Break]] = [
    ("missing reply", "Missing or duplicate cleanup reply", drop_reply),
    ("reference parity", "Cleanup download reference parity differs", odd_to_even),
    ("advertised size", "Cleanup advertised size differs", wrong_advertised),
    ("logical size", "Cleanup logical size differs", wrong_logical),
    ("greeting", "Cleanup HTXF differs", wrong_greeting),
    ("prefix", "Cancelled data is not a baseline prefix", flip_received),
    (
        "partial bound",
        "Race did not establish bounded partial delivery",
        truncate_received,
    ),
    ("owner ACK", "Owner/duplicate cleanup ACK differs", wrong_owner_ack),
    ("duplicate ACK", "Owner/duplicate cleanup ACK differs", wrong_duplicate_ack),
    ("native close", "Missing native cleanup close", no_native_close),
    ("stale reuse", "Removed reference reattached successfully", stale_delivers),
    ("stale greeting", "Stale-reference header differs", wrong_stale_greeting),
    ("read ordering", "Application receive/cancel ordering differs", extra_read),
]


def broken_download(first: int) -> Subject:
    """Break the download case from check ``first`` on.

    The breaks are applied last to first, so that the removal of the reply to
    request 10 comes after the breaks that edit it.

    The prefix break flips a byte that the partial-bound break keeps, so the two
    can be applied together.

    Returns
    -------
    Subject
        The broken case.
    """
    subject = Subject("cleanup-partial-1")
    for _label, _message, apply in reversed(DOWNLOAD_BREAKS[first:]):
        apply(subject)
    return subject


def run_download(subject: Subject) -> Report:
    """Check a download case the way the corpus check does.

    Returns
    -------
    dict[str, typing.Any]
        The measurements.
    """
    return check_download(
        subject.report,
        {"variant": "partial-1", "prefix_size": PARTIAL_PREFIX},
        subject.baseline,
        subject.packets,
        read_packets(BATCH / "guest.pcap"),
    )


class DownloadCheckOrderTests:
    """Keep the download checks in the order in which they have always run."""

    def test_the_unbroken_case_passes(self) -> None:
        """The retained partial case is accepted, so each break is the cause."""
        result = run_download(Subject("cleanup-partial-1"))
        assert result["received_stream_bytes"] >= PARTIAL_PREFIX, (
            "the partial case did not reach its prefix"
        )

    @pytest.mark.parametrize("first", range(len(DOWNLOAD_BREAKS)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        _label, message, _apply = DOWNLOAD_BREAKS[first]
        with pytest.raises(ValueError, match=message):
            run_download(broken_download(first))


def wrong_upload_reference(subject: Subject) -> None:
    """Give the upload an odd reference, which is a download's."""
    set_field(frame(subject.report, 10), 107, "00000003")


def wrong_upload_body(subject: Subject) -> None:
    """Record an upload stream that is not the greeting and body."""
    subject.stream("upload")["sent_hex"] = "00"


def upload_receives(subject: Subject) -> None:
    """Let the upload connection receive bytes."""
    subject.stream("upload")["received_hex"] = "00"


def no_upload_close(subject: Subject) -> None:
    """Report that the guest did not close the upload connection."""
    subject.packets["upload"]["guest_server_initiated_close"] = False


def renamed_file(subject: Subject) -> None:
    """Make the file-info reply name another file."""
    set_field(frame(subject.report, 12), 201, "00")


def wrong_info_size(subject: Subject) -> None:
    """Make the file-info reply report another size."""
    set_field(frame(subject.report, 12), 207, WRONG_SIZE)


def wrong_upload_ack(subject: Subject) -> None:
    """Make the first cleanup ACK of the upload case carry a payload."""
    frame(subject.report, 11)["payload_hex"] = NONZERO_ACK


UPLOAD_BREAKS: list[tuple[str, str, Break]] = [
    ("missing reply", "Missing or duplicate cleanup reply", drop_reply),
    ("reference parity", "Cleanup upload reference differs", wrong_upload_reference),
    ("body", "Cleanup upload body differs", wrong_upload_body),
    ("received", "Cleanup upload completion differs", upload_receives),
    ("close", "Cleanup upload completion differs", no_upload_close),
    ("file name", "Request name did not survive upload", renamed_file),
    ("file size", "File-info size differs", wrong_info_size),
    ("cleanup ACK", "Upload214 ACK differs", wrong_upload_ack),
]


class UploadCheckOrderTests:
    """Keep the upload checks in the order in which they have always run."""

    @pytest.mark.parametrize("first", range(len(UPLOAD_BREAKS)))
    def test_the_first_broken_check_is_the_one_reported(self, first: int) -> None:
        """Breaking checks ``first`` onward reports the check at ``first``."""
        subject = Subject("cleanup-pending-upload")
        for _label, _message, apply in reversed(UPLOAD_BREAKS[first:]):
            apply(subject)
        _label, message, _apply = UPLOAD_BREAKS[first]
        expectation = {"kind": "cleanup-upload", "name_hex": b"mothra-214-upload".hex()}
        with pytest.raises(ValueError, match=message):
            check_upload(subject.report, expectation, subject.packets)


class CorpusCheckOrderTests:
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

    def test_packets_are_read_before_the_inventory(self, tmp_path: Path) -> None:
        """A missing host capture is reported although the inventory is wrong."""
        directory = self.copy_corpus(tmp_path)
        (directory / "host.pcap").unlink()
        (directory / "transcripts/unexpected").mkdir()
        with pytest.raises(FileNotFoundError):
            verify(directory)

    def test_the_inventory_precedes_the_unread_output(self, tmp_path: Path) -> None:
        """A wrong case list is reported although the unread output is wrong."""
        directory = self.copy_corpus(tmp_path)
        (directory / "transcripts/unexpected").mkdir()
        (directory / "unread-output.json").write_text("{}")
        with pytest.raises(ValueError, match="Cleanup corpus inventory differs"):
            verify(directory)

    def test_the_unread_inventory_precedes_the_native_files(
        self, tmp_path: Path
    ) -> None:
        """A wrong unread inventory is reported although a native file differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "unread-output.json").write_text("{}")
        (directory / "native-files/mothra-race-fixture.data").write_bytes(b"x")
        with pytest.raises(ValueError, match="Unread cleanup inventory differs"):
            verify(directory)

    def test_the_departure_precedes_the_native_files(self, tmp_path: Path) -> None:
        """A wrong unread departure is reported although a native file differs."""
        directory = self.copy_corpus(tmp_path)
        path = directory / "unread-output.json"
        unread = json.loads(path.read_text())
        value = unread["cleanup-nonowner"]["a"]
        unread["cleanup-nonowner"]["a"] = value[:4] + NOT_A_DEPARTURE + value[8:]
        path.write_text(json.dumps(unread))
        (directory / "native-files/mothra-race-fixture.data").write_bytes(b"x")
        with pytest.raises(ValueError, match="Unread departure differs"):
            verify(directory)
