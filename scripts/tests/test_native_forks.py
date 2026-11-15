"""Check complete fork bytes and reject evidence that omits native outcomes."""

import json
import shutil
from pathlib import Path

import pytest
from native_filp import decode, metadata
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from verify_native_forks import verify

BATCH = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-12/native-forks-01"
)
CASES = 10
HYPOTHESES = 8
RAW_BYTES = 510
FLIPPED_RESOURCE_BYTE = 260


class ForkTests:
    """Check complete fork bytes and reject evidence that omits native outcomes."""

    def test_native_transfers_and_filesystem_forks(self) -> None:
        """The retained corpus verifies, with its ten cases and eight hypotheses."""
        result = verify(BATCH)
        assert len(result["cases"]) == CASES, "expected the ten retained cases"
        assert len(result["initial_eof_hypotheses"]) == HYPOTHESES, (
            "expected the eight initial hypotheses"
        )
        raw = next(c for c in result["cases"] if c["case"] == "download-raw")
        assert raw["advertised_bytes"] == RAW_BYTES, "expected 510 advertised bytes"
        assert raw["metadata"]["flags"] == "00000000", "expected zero metadata flags"

    def test_truncated_resource_and_trailing_data_are_rejected(self) -> None:
        """A truncated stream, trailing bytes and a short INFO are refused."""
        report = json.loads(
            (BATCH / "transcripts/download-raw/report.json").read_text()
        )
        data = bytes.fromhex(report["streams"]["download"]["received_hex"])
        for value in [data[:-1], data + b"extra"]:
            with pytest.raises(ValueError):  # ruff: ignore[pytest-raises-too-broad]  # the original asserted the exception type only
                decode(value)
        info = decode(data)["INFO"]
        with pytest.raises(ValueError, match="comment length"):
            metadata(info[:-1])

    def test_socket_prefix_cannot_silently_discard_unread_native_output(self) -> None:
        """Unread native output is not discarded when the packets are compared."""
        report = json.loads(
            (BATCH / "transcripts/download-empty/report.json").read_text()
        )
        with pytest.raises(ValueError, match="host output differs"):
            reconcile(
                report,
                read_packets(BATCH / "host.pcap"),
                read_packets(BATCH / "guest.pcap"),
            )

    def test_network_success_does_not_substitute_for_native_fork_bytes(
        self, tmp_path: Path
    ) -> None:
        """A changed native resource fork is refused despite a clean network run."""
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        resource = directory / "native-files/mothra-fork-fixture.rsrc"
        raw = bytearray(resource.read_bytes())
        raw[FLIPPED_RESOURCE_BYTE] ^= 1
        resource.write_bytes(raw)
        with pytest.raises(ValueError, match="Native resource fork differs"):
            verify(directory)
