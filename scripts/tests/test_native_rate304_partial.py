"""Semantic fault controls for the failed 304 first-pair corpus."""

import contextlib
import hashlib
import json
import re
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from verify_native_rate304_partial import CORPUS, verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc


class PartialCorpusTest:
    """Reject each semantic fault that the failed 304 first-pair corpus can carry."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    @pytest.fixture(autouse=True)
    def setUp(self) -> cabc.Iterator[None]:
        """Copy the retained corpus into a temporary directory removed afterwards.

        Yields
        ------
        None
            Control returns to the test once the copy exists.
        """
        with contextlib.ExitStack() as stack:
            temp = stack.enter_context(tempfile.TemporaryDirectory())
            self.corpus = Path(temp) / CORPUS.name
            shutil.copytree(CORPUS, self.corpus)
            yield

    def refresh(self) -> None:
        """Recompute the manifest's file hashes and SHA256SUMS for the copy."""
        files = {
            str(path.relative_to(self.corpus)): hashlib.sha256(
                path.read_bytes()
            ).hexdigest()
            for path in self.corpus.rglob("*")
            if path.is_file() and path.name not in {"manifest.json", "SHA256SUMS"}
        }
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["files"] = dict(sorted(files.items()))
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(f"{digest}  {name}\n" for name, digest in sorted(files.items()))
        )

    def change_report(
        self,
        edit: cabc.Callable[[dict[str, typ.Any]], None],
        message: str,
    ) -> None:
        """Edit the coordinator report, refresh the copy and expect a rejection.

        Parameters
        ----------
        edit : cabc.Callable[[dict[str, typ.Any]], None]
            The change to make to the parsed coordinator report.
        message : str
            The message of the ValueError that the verifier must raise.
        """
        path = self.corpus / "raw/coordinator/report.json"
        report = json.loads(path.read_text())
        edit(report)
        path.write_text(json.dumps(report, indent=2) + "\n")
        self.refresh()
        with pytest.raises(ValueError, match=re.escape(message)):
            verify(self.corpus)

    def test_frozen_failure_replays(self) -> None:
        """Replay the frozen failure without a change."""
        verify(self.corpus)

    def test_zero_304_is_rejected(self) -> None:
        """Reject a report whose 304 action is missing."""
        self.change_report(
            lambda report: report["actions"].pop(4), "Case action boundary differs"
        )

    def test_missing_late_barrier_ack_is_rejected(self) -> None:
        """Reject a report whose late barrier acknowledgement is missing."""
        self.change_report(
            lambda report: report["frames"].__setitem__(
                slice(None), [f for f in report["frames"] if f["id"] != 2000]
            ),
            "Case frame count differs",
        )

    def test_wrong_icon_is_rejected(self) -> None:
        """Reject a paced presence notice that carries the wrong icon."""

        def edit(report: dict[str, typ.Any]) -> None:
            """Set the icon of the paced presence notice to the wrong value."""
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "paced" and f["type"] == 301
            )
            next(field for field in frame["fields"] if field["id"] == 104)["hex"] = (
                "0001"
            )

        self.change_report(
            edit, "Initial join, late update, ACK or cleanup departure differs"
        )

    def test_false_observer_update_is_rejected(self) -> None:
        """Reject an observer presence notice that carries a false icon."""

        def edit(report: dict[str, typ.Any]) -> None:
            """Set the icon of the observer presence notice to the false value."""
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "observer" and f["type"] == 301
            )
            next(field for field in frame["fields"] if field["id"] == 104)["hex"] = (
                "0002"
            )

        self.change_report(
            edit, "Initial join, late update, ACK or cleanup departure differs"
        )

    def test_early_response_timing_is_rejected(self) -> None:
        """Reject a paced presence notice that arrives too early."""

        def edit(report: dict[str, typ.Any]) -> None:
            """Move the arrival of the paced presence notice forward."""
            frame = next(
                f
                for f in report["frames"]
                if f["connection"] == "paced" and f["type"] == 301
            )
            frame["arrival_elapsed_ns"] = 900_000_000

        self.change_report(edit, "First-pair timing or client cleanup differs")

    def test_packet_byte_mutation_is_rejected(self) -> None:
        """Reject a capture whose packet bytes were changed."""
        path = self.corpus / "raw/lab-namespace.pcap"
        data = bytearray(path.read_bytes())
        needle = bytes.fromhex("00000130000003e8")
        index = data.index(needle)
        data[index + 7] ^= 1
        path.write_bytes(data)
        self.refresh()
        with pytest.raises(
            ValueError, match=re.escape("paced packet stream differs from recorder")
        ):
            verify(self.corpus)

    def test_missing_flow_is_rejected(self) -> None:
        """Reject a capture that is truncated to a bare header."""
        path = self.corpus / "raw/lab-namespace.pcap"
        path.write_bytes(path.read_bytes()[:24])
        self.refresh()
        with pytest.raises(ValueError, match=re.escape("Capture packet count differs")):
            verify(self.corpus)

    def test_false_terminal_success_is_rejected(self) -> None:
        """Reject a report that claims a completed status."""
        self.change_report(
            lambda report: report.__setitem__("status", "completed"),
            "Failed-case status or source differs",
        )

    def test_false_capture_drop_status_is_rejected(self) -> None:
        """Reject a capture journal that reports a kernel drop."""
        path = self.corpus / "raw/capture-journal-terminal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel", 1
            )
        )
        self.refresh()
        with pytest.raises(
            ValueError,
            match=re.escape("Recorder drop or primary-contact proof differs"),
        ):
            verify(self.corpus)
