"""Reject semantic and packet faults even after the mutable inventory is rehashed."""

import hashlib
import json
import shutil
import tempfile
import typing as typ
from pathlib import Path

import pytest
from verify_native_settings_corpus import verify

if typ.TYPE_CHECKING:
    import collections.abc as cabc

BUNDLE = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-settings-01"
)
PAIRED_SOCKETS = 24
CASE_COUNT = 10
FILP_BYTES = 1049073


def digest(path: Path) -> str:
    """Hash a file.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def edit_report(path: Path, change: cabc.Callable[[dict[str, typ.Any]], None]) -> Path:
    """Change the JSON of a report in place.

    Parameters
    ----------
    path : pathlib.Path
        The report.
    change : collections.abc.Callable[[dict[str, typing.Any]], None]
        The change to make to the parsed report.

    Returns
    -------
    pathlib.Path
        The report's path.
    """
    report = json.loads(path.read_text())
    change(report)
    path.write_text(json.dumps(report) + "\n")
    return path


def wrong_flags(bundle: Path) -> Path:
    """Change the feedback option of the one-byte refusal case to automatic.

    Returns
    -------
    pathlib.Path
        The changed report.
    """

    def change(report: dict[str, typ.Any]) -> None:
        """Set field 113 of the feedback to ``0004``."""
        feedback = next(
            f
            for f in report["frames"]
            if f["connection"] == "main" and f["type"] == 104
        )
        next(f for f in feedback["fields"] if f["id"] == 113)["hex"] = "0004"

    return edit_report(bundle / "raw/cases/one-byte-refuse/report.json", change)


def missing_delivery(bundle: Path) -> Path:
    """Remove the subject's delivery from the case that has no refusal.

    Returns
    -------
    pathlib.Path
        The changed report.
    """

    def change(report: dict[str, typ.Any]) -> None:
        """Drop the 104 frames that the subject received."""
        report["frames"] = [
            f
            for f in report["frames"]
            if not (f["connection"] == "subject" and f["type"] == 104)
        ]

    return edit_report(bundle / "raw/cases/absent/report.json", change)


def spoofed_uid(bundle: Path) -> Path:
    """Change the subject's user id in the second presence update.

    Returns
    -------
    pathlib.Path
        The changed report.
    """

    def change(report: dict[str, typ.Any]) -> None:
        """Set field 103 of the second 301 to ``ffff``."""
        updates = [
            f
            for f in report["frames"]
            if f["connection"] == "main" and f["type"] == 301
        ]
        next(f for f in updates[1]["fields"] if f["id"] == 103)["hex"] = "ffff"

    return edit_report(bundle / "raw/cases/absent/report.json", change)


def altered_host_pcap(bundle: Path) -> Path:
    """Change the first byte of the host capture.

    Returns
    -------
    pathlib.Path
        The changed capture.
    """
    path = bundle / "raw/host.pcap"
    value = bytearray(path.read_bytes())
    value[0] ^= 0xFF
    path.write_bytes(value)
    return path


def shortened_a7_data(bundle: Path) -> Path:
    """Drop the last byte of the A7 download in the postflight report.

    Returns
    -------
    pathlib.Path
        The changed report.
    """

    def change(report: dict[str, typ.Any]) -> None:
        """Shorten the received hex by one byte."""
        download = report["streams"]["download"]
        download["received_hex"] = download["received_hex"][:-2]

    return edit_report(bundle / "raw/postflight/capture/report.json", change)


class NativeSettingsCorpusTests:
    """Reject semantic and packet faults even after the inventory is rehashed."""

    def mutate(self, change: cabc.Callable[[Path], Path], reason: str) -> None:
        """Change a copy of the bundle, rehash it and expect a rejection.

        Parameters
        ----------
        change : collections.abc.Callable[[pathlib.Path], pathlib.Path]
            The change to make to the copied bundle; it returns the changed file.
        reason : str
            A regular expression that the rejection message must match.
        """
        with tempfile.TemporaryDirectory() as directory:
            bundle = Path(directory) / "bundle"
            shutil.copytree(BUNDLE, bundle)
            changed = change(bundle)
            if changed.name == "report.json":
                capture = changed.parent
                (capture / "checksums.sha256").write_text(
                    "".join(
                        f"{digest(capture / name)}  {name}\n"
                        for name in ["plan.json", "report.json"]
                    )
                )
            raw = bundle / "raw"
            (raw / "SHA256SUMS").write_text(
                "".join(
                    f"{digest(path)}  {path.relative_to(raw)}\n"
                    for path in sorted(raw.rglob("*"))
                    if path.is_file() and path.name != "SHA256SUMS"
                )
            )
            manifest = json.loads((bundle / "manifest.json").read_text())
            manifest["raw_sha256sums_sha256"] = digest(raw / "SHA256SUMS")
            (bundle / "manifest.json").write_text(json.dumps(manifest) + "\n")
            with pytest.raises(ValueError, match=reason):
                verify(bundle)

    def test_original_offline_bundle(self) -> None:
        """The retained bundle verifies, with ten cases and 24 paired sockets."""
        result = verify(BUNDLE)
        assert (result["status"], len(result["cases"]), result["paired_sockets"]) == (
            "verified",
            CASE_COUNT,
            PAIRED_SOCKETS,
        ), "expected the recorded counts"
        assert result["a7"]["postflight"]["filp_bytes"] == FILP_BYTES, "FILP length"

    def test_rehashed_wrong_flags(self) -> None:
        """A feedback option that contradicts the refusal is rejected."""
        self.mutate(wrong_flags, "Field-113 state differs")

    def test_rehashed_missing_delivery(self) -> None:
        """A missing delivery without refusal feedback is rejected."""
        self.mutate(missing_delivery, "Suppression without refusal feedback")

    def test_rehashed_spoofed_uid(self) -> None:
        """A changed subject user id in the second update is rejected."""
        self.mutate(spoofed_uid, "Subject UID changed")

    def test_rehashed_altered_host_pcap(self) -> None:
        """A changed byte in the host capture is rejected as a bad capture."""
        self.mutate(altered_host_pcap, "PCAP")

    def test_rehashed_shortened_a7_data(self) -> None:
        """A shortened A7 download is rejected."""
        self.mutate(shortened_a7_data, "A7 FILP transfer length differs")
