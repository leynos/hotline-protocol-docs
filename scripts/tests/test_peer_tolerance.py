"""Adversarial checks for the frozen full-process peer evidence."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from verify_peer_tolerance import verify

# scripts/tests sits two levels below the repository root that holds evidence/.
ROOT = Path(__file__).resolve().parents[2]
SOURCE = ROOT / "evidence/gap-remediation/2026-11-13"
CORPUS = SOURCE / "delegated-peer-01"


def changed_copy(tmp_path: Path) -> Path:
    """Copy the frozen peer corpus into a fresh directory for one edit.

    Returns
    -------
    pathlib.Path
        The copy, which the test may change.
    """
    target = tmp_path / "corpus"
    shutil.copytree(CORPUS, target)
    return target


def rewrite_sums(corpus: Path) -> None:
    """Rewrite the checksum file of an edited copy so only the edit is judged."""
    prefix = CORPUS.relative_to(ROOT)
    lines = []
    for path in sorted(corpus.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {prefix / path.relative_to(corpus)}\n")
    (corpus / "SHA256SUMS").write_text("".join(lines))


class PeerToleranceEvidenceTests:
    """Reject changed peer identity, fixture bytes and banner order."""

    def test_frozen_matrix_verifies(self) -> None:
        """The frozen matrix verifies with its five cases in recorded order."""
        result = verify(CORPUS, SOURCE)
        assert result["status"] == "verified", "the frozen corpus did not verify"
        assert [row["case"] for row in result["cases"]] == [
            "control",
            "omit-161",
            "vary-161",
            "unknown-login",
            "early-122",
        ], "the case order differs"

    def test_wrong_peer_identity_rejected_with_fresh_checksums(
        self, tmp_path: Path
    ) -> None:
        """A changed peer binary digest is rejected even with fresh checksums."""
        corpus = changed_copy(tmp_path)
        path = corpus / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest["peer_binary_sha256"] = "0" * 64
        path.write_text(json.dumps(manifest))
        rewrite_sums(corpus)
        with pytest.raises(ValueError, match="identity"):
            verify(corpus, SOURCE)

    def test_wrong_login_field_rejected_with_fresh_checksums(
        self, tmp_path: Path
    ) -> None:
        """A login field that differs from the fixture bytes is rejected."""
        corpus = changed_copy(tmp_path)
        path = corpus / "fixtures/vary-161/report.json"
        report = json.loads(path.read_text())
        send = next(event for event in report["events"] if event["event"] == "send")
        assert "00a100020001" in send["hex"], "the recorded login field is absent"
        send["hex"] = send["hex"].replace("00a100020001", "00a100020002", 1)
        path.write_text(json.dumps(report))
        rewrite_sums(corpus)
        with pytest.raises(ValueError, match="Fixture bytes"):
            verify(corpus, SOURCE)

    def test_wrong_banner_order_rejected_with_fresh_checksums(
        self, tmp_path: Path
    ) -> None:
        """Swapping two early sends in the fixture is rejected."""
        corpus = changed_copy(tmp_path)
        path = corpus / "fixtures/early-122/report.json"
        report = json.loads(path.read_text())
        sends = [event for event in report["events"] if event["event"] == "send"]
        assert len(sends) >= 3, "the early banner case has too few sends"
        sends[1]["hex"], sends[2]["hex"] = sends[2]["hex"], sends[1]["hex"]
        path.write_text(json.dumps(report))
        rewrite_sums(corpus)
        with pytest.raises(ValueError, match="Fixture bytes"):
            verify(corpus, SOURCE)
