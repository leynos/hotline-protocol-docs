"""Negative controls for the public redacted A22 witness."""

import json
import shutil
import typing as typ

import pytest
from verify_mxd_classic_login import CORPUS, digest, verify_public

if typ.TYPE_CHECKING:
    from pathlib import Path


class WitnessTests:
    """Reject altered public witnesses, including ones with refreshed checksums."""

    @pytest.fixture
    def corpus(self, tmp_path: Path) -> Path:
        """Copy the retained witness into a scratch directory.

        Returns
        -------
        pathlib.Path
            The scratch copy of the redacted witness directory.
        """
        copy = tmp_path / "corpus"
        shutil.copytree(CORPUS, copy)
        return copy

    def _rewrite_witness(self, corpus: Path, change: str) -> None:
        """Change one witness field and refresh its checksum entry."""
        path = corpus / "redacted-witness.json"
        record = json.loads(path.read_text())
        match change:
            case "status":
                record["decoded_public"]["reply_status"] = 0
            case "length":
                record["private_replay"]["wire_field106_length"] = 48
        path.write_text(json.dumps(record, indent=2) + "\n")
        checks = corpus / "SHA256SUMS"
        refreshed = []
        for line in checks.read_text().splitlines():
            name = line.split("  ", 1)[1]
            refreshed.append(f"{digest((corpus / name).read_bytes())}  {name}")
        checks.write_text("\n".join(refreshed) + "\n")

    def test_public_explicitly_lacks_raw_proof(self, corpus: Path) -> None:
        """The public witness must state that raw packet proof is unavailable."""
        result = verify_public(corpus)
        assert result["status"] == "metadata-only", "the status must be metadata-only"
        assert result["raw_packet_proof"] == "unavailable", (
            "the raw packet proof must be reported as unavailable"
        )

    def test_changed_checksum_fails(self, corpus: Path) -> None:
        """A changed listed file must fail its checksum."""
        (corpus / "actions-redacted.txt").write_text("changed\n")
        with pytest.raises(AssertionError):
            verify_public(corpus)

    def test_success_relabel_fails_after_checksum_refresh(self, corpus: Path) -> None:
        """A success relabel must fail even with a refreshed checksum."""
        self._rewrite_witness(corpus, "status")
        with pytest.raises(AssertionError):
            verify_public(corpus)

    def test_wrong_password_length_fails_after_checksum_refresh(
        self, corpus: Path
    ) -> None:
        """A wrong password length must fail even with a refreshed checksum."""
        self._rewrite_witness(corpus, "length")
        with pytest.raises(AssertionError):
            verify_public(corpus)
