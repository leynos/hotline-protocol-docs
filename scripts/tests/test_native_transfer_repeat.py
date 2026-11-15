"""Semantic fault controls for the three-run frozen transfer corpus."""

import hashlib
import json
import shutil
import struct
from pathlib import Path

import pytest
from verify_native_transfer_repeat import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/native-transfer-repeat-01"
)


@pytest.fixture
def corpus(tmp_path: Path) -> Path:
    """Copy the retained transfer corpus so a test may alter it.

    Returns
    -------
    pathlib.Path
        The writable copy, named as the retained corpus directory.
    """
    target = tmp_path / "native-transfer-repeat-01"
    shutil.copytree(CORPUS, target)
    return target


def reseal(corpus: Path, relative: str) -> None:
    """Update the provenance, manifest and checksum files for one altered file."""
    provenance_path = corpus / "source-provenance.json"
    provenance = json.loads(provenance_path.read_text())
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
            f"{digest}  {name}\n" for name, digest in sorted(manifest["files"].items())
        )
    )


def write_checksums(checksums: Path, names: tuple[str, ...]) -> None:
    """Write a checksum list naming ``names`` in the directory of ``checksums``."""
    lines: list[str] = []
    for name in names:
        digest = hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()
        lines.append(f"{digest}  {name}\n")
    checksums.write_text("".join(lines))


class TransferRepeatTests:
    """Resealed alterations of the transfer repeat corpus must still be rejected."""

    def test_complete_and_two_failed_streams_replay(self) -> None:
        """The retained corpus replays with matching failed-stream byte counts."""
        results = verify(CORPUS)
        assert results["c32"]["bytes"] == 1_049_073, "expected the c32 byte count"
        assert results["c35"]["bytes"] == results["c45"]["bytes"], (
            "expected the failed streams to carry equal byte counts"
        )

    def test_resealed_failed_report_cannot_claim_completion(self, corpus: Path) -> None:
        """A failed report relabelled as completed, then resealed, is rejected."""
        relative = "runs/c45/capture/report.json"
        path = corpus / relative
        report = json.loads(path.read_text())
        report["status"] = "completed"
        path.write_text(json.dumps(report, indent=2) + "\n")
        write_checksums(
            path.with_name("checksums.sha256"), ("plan.json", "report.json")
        )
        reseal(corpus, relative)
        reseal(corpus, "runs/c45/capture/checksums.sha256")
        with pytest.raises(ValueError, match="Incomplete plan reported as completed"):
            verify(corpus)

    def test_resealed_success_pcap_missing_byte_is_rejected(self, corpus: Path) -> None:
        """A flipped byte in the last server packet is rejected after resealing."""
        relative = "runs/c32/boot/lab-guest.pcap"
        path = corpus / relative
        data = bytearray(path.read_bytes())
        comparison = json.loads(
            (corpus / "analysis/packet-comparison.json").read_text()
        )
        index = comparison["runs"]["c32"]["views"]["guest"]["last_server_packet_index"]
        offset = 24
        for number in range(1, index + 1):
            _, _, size, _ = struct.unpack_from("<IIII", data, offset)
            if number == index:
                data[offset + 16 + size - 1] ^= 1
                break
            offset += 16 + size
        path.write_bytes(data)
        reseal(corpus, relative)
        with pytest.raises(ValueError, match="c32 guest payload differs"):
            verify(corpus)

    def test_resealed_changed_a7_step_is_rejected(self, corpus: Path) -> None:
        """A plan with a missing final step is rejected after resealing."""
        relative = "runs/c35/original-plan.json"
        path = corpus / relative
        plan = json.loads(path.read_text())
        plan["steps"].pop()
        path.write_text(json.dumps(plan, indent=2) + "\n")
        reseal(corpus, relative)
        with pytest.raises(ValueError, match="c35 source A7 differs"):
            verify(corpus)

    def test_resealed_c45_cleanup_scope_is_rejected(self, corpus: Path) -> None:
        """A terminal record claiming the option-two probe ran is rejected."""
        relative = "runs/c45/terminal.json"
        path = corpus / relative
        terminal = json.loads(path.read_text())
        terminal["guard_seed_ban_probe"] = "option two executed"
        path.write_text(json.dumps(terminal, indent=2) + "\n")
        reseal(corpus, relative)
        with pytest.raises(ValueError, match="C45 option-two scope differs"):
            verify(corpus)
