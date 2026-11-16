"""Fault controls for the frozen C50 focus-event result."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest
from pcap_tcp import read_packets
from verify_native_ui_focus import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/native-ui-focus-01"
)


def file_sha256(path: Path) -> str:
    """Hash a file's bytes.

    Returns
    -------
    str
        The hexadecimal SHA-256 of the file.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


class NativeUiFocusTests:
    """Replay the frozen focus event and reject each resealed fault."""

    @pytest.fixture(autouse=True)
    def _scratch_corpus(self, tmp_path: Path) -> None:
        """Copy the frozen corpus into a scratch directory that a test may change."""
        self.corpus = tmp_path / "native-ui-focus-01"
        shutil.copytree(CORPUS, self.corpus)

    def reseal(self, relative: str) -> None:
        """Recompute the recorded hashes of one changed file and of its manifest.

        Parameters
        ----------
        relative : str
            The changed file, relative to the corpus.
        """
        provenance_path = self.corpus / "source-provenance.json"
        provenance = json.loads(provenance_path.read_text(encoding="utf-8"))
        path = self.corpus / relative
        provenance["sources"][relative]["sha256"] = file_sha256(path)
        provenance["sources"][relative]["bytes"] = path.stat().st_size
        provenance_path.write_text(
            json.dumps(provenance, indent=2) + "\n", encoding="utf-8"
        )
        manifest_path = self.corpus / "manifest.json"
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for name in (relative, "source-provenance.json"):
            manifest["files"][name] = file_sha256(self.corpus / name)
        manifest_path.write_text(
            json.dumps(manifest, indent=2) + "\n", encoding="utf-8"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(
                f"{digest}  {name}\n"
                for name, digest in sorted(manifest["files"].items())
            ),
            encoding="utf-8",
        )

    def test_frozen_negative_focus_replays(self) -> None:
        """Replay the frozen corpus and expect the negative focus result."""
        result = verify(CORPUS)
        assert result["guest_bytes"] == 98_304, "guest view length differs"
        assert result["event_count"] == 1, "focus event count differs"
        assert not result["option_two_executed"], "option two was executed"

    def test_resealed_zero_click_claim_is_rejected(self) -> None:
        """A resealed zero-click claim fails the focus outcome check."""
        relative = "experiment/focus-event/result.json"
        path = self.corpus / relative
        result = json.loads(path.read_text(encoding="utf-8"))
        result["event_count"] = 0
        path.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
        self.reseal(relative)
        with pytest.raises(ValueError, match="Focus event outcome differs"):
            verify(self.corpus)

    def test_resealed_unchanged_title_is_rejected(self) -> None:
        """A resealed after-image with the unchanged title fails the title check."""
        relative = "experiment/focus-event/after.png"
        path = self.corpus / relative
        path.write_bytes(path.with_name("before.png").read_bytes())
        self.reseal(relative)
        with pytest.raises(ValueError, match="Activated Log title differs"):
            verify(self.corpus)

    def test_resealed_guest_payload_corruption_is_rejected(self) -> None:
        """A resealed flip in the guest payload fails the stream comparison."""
        relative = "boot/lab-guest.pcap"
        path = self.corpus / relative
        packets = read_packets(path)
        index = next(
            p["index"]
            for p in packets
            if p["src_ip"] == "10.0.2.15" and p["src_port"] == 5501 and p["payload_hex"]
        )
        raw = bytearray(path.read_bytes())
        offset = 24
        for number in range(1, index + 1):
            _, _, size, _ = struct.unpack_from("<IIII", raw, offset)
            if number == index:
                raw[offset + 16 + size - 1] ^= 1
                break
            offset += 16 + size
        path.write_bytes(raw)
        self.reseal(relative)
        with pytest.raises(ValueError, match="guest packet stream differs"):
            verify(self.corpus)

    def test_resealed_false_a7_success_is_rejected(self) -> None:
        """A resealed false A7 success fails the plan completion check."""
        relative = "experiment/capture/report.json"
        path = self.corpus / relative
        report = json.loads(path.read_text(encoding="utf-8"))
        report["status"] = "completed"
        path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        checksums = path.with_name("checksums.sha256")
        checksums.write_text(
            "".join(
                f"{file_sha256(checksums.parent / name)}  {name}\n"
                for name in ("plan.json", "report.json")
            ),
            encoding="utf-8",
        )
        self.reseal(relative)
        self.reseal("experiment/capture/checksums.sha256")
        with pytest.raises(ValueError, match="Incomplete plan reported as completed"):
            verify(self.corpus)
