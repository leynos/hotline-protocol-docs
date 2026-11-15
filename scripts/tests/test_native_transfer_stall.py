"""Meaningful offline fault controls for the C35 failed-transfer corpus."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest
from verify_native_transfer_stall import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-transfer-stall-01"
)
RECEIVE_WINDOW_PACKET = 178


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Copy the retained stall corpus so a test may alter it.

    Returns
    -------
    pathlib.Path
        The writable copy, named as the retained corpus directory.
    """
    target = tmp_path / "native-transfer-stall-01"
    shutil.copytree(CORPUS, target)
    return target


def reseal(corpus: Path, relative: str) -> None:
    """Update the provenance, manifest and checksum files for one altered file."""
    provenance_path = corpus / "source-provenance.json"
    provenance = json.loads(provenance_path.read_text())
    if relative in provenance["sources"]:
        path = corpus / relative
        provenance["sources"][relative]["sha256"] = hashlib.sha256(
            path.read_bytes()
        ).hexdigest()
        provenance["sources"][relative]["bytes"] = path.stat().st_size
        provenance_path.write_text(json.dumps(provenance, indent=2) + "\n")
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    for name in (relative, "source-provenance.json"):
        manifest["files"][name] = hashlib.sha256(
            (corpus / name).read_bytes()
        ).hexdigest()
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n")
    (corpus / "SHA256SUMS").write_text(
        "".join(
            f"{value}  {name}\n" for name, value in sorted(manifest["files"].items())
        )
    )


def write_checksums(checksums: Path, names: tuple[str, ...]) -> None:
    """Write a checksum list naming ``names`` in the directory of ``checksums``."""
    lines: list[str] = []
    for name in names:
        digest = hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    checksums.write_text("".join(lines))


class TransferStallTests:
    """Resealed alterations of the failed-transfer corpus must still be rejected."""

    def test_original_failure_and_packet_views_replay(self) -> None:
        """The retained failure replays as a verified failed baseline."""
        result = verify(CORPUS)
        assert result["status"] == "verified_failed_baseline", (
            "expected the retained failure to replay as the failed baseline"
        )
        assert not result["option_two_executed"], "expected option two not to run"

    def test_resealed_success_claim_cannot_replace_failed_report(
        self, corpus: Path
    ) -> None:
        """A failed report relabelled as completed, then resealed, is rejected."""
        relative = "failure/report.json"
        path = corpus / relative
        report = json.loads(path.read_text())
        report["status"] = "completed"
        path.write_text(json.dumps(report, indent=2) + "\n")
        write_checksums(
            corpus / "failure/checksums.sha256", ("plan.json", "report.json")
        )
        reseal(corpus, relative)
        reseal(corpus, "failure/checksums.sha256")
        with pytest.raises(ValueError, match="Incomplete plan reported as completed"):
            verify(corpus)

    def test_resealed_zero_receive_window_changes_h2_result(self, corpus: Path) -> None:
        """A zeroed receive window in the namespace capture is rejected."""
        relative = "capture/namespace.pcap"
        path = corpus / relative
        raw = bytearray(path.read_bytes())
        offset = 24
        for index in range(1, RECEIVE_WINDOW_PACKET + 1):
            _, _, size, _ = struct.unpack_from("<IIII", raw, offset)
            if index == RECEIVE_WINDOW_PACKET:
                ip = offset + 16 + 14
                tcp = ip + (raw[ip] & 15) * 4
                raw[tcp + 14 : tcp + 16] = b"\0\0"
                break
            offset += 16 + size
        path.write_bytes(raw)
        reseal(corpus, relative)
        with pytest.raises(ValueError, match="namespace zero window"):
            verify(corpus)

    def test_resealed_truncated_guest_packet_is_rejected(self, corpus: Path) -> None:
        """A guest capture missing its final byte is rejected after resealing."""
        relative = "capture/guest.pcap"
        path = corpus / relative
        path.write_bytes(path.read_bytes()[:-1])
        reseal(corpus, relative)
        with pytest.raises(ValueError, match="Truncated packet bytes"):
            verify(corpus)
