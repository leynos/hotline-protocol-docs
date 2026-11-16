"""Fault controls for the frozen send-path replay."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from verify_native_download_send_path import verify

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/native-download-send-path-01"
)


def reseal(corpus: Path, name: str) -> None:
    """Recompute the digests of a changed file and of the records that list it.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory, which is altered in place.
    name : str
        The file within the corpus that was changed.
    """
    digest = hashlib.sha256((corpus / name).read_bytes()).hexdigest()
    provenance = corpus / "source-provenance.json"
    record = json.loads(provenance.read_text())
    record["sources"][name]["sha256"] = digest
    record["sources"][name]["bytes"] = (corpus / name).stat().st_size
    provenance.write_text(json.dumps(record, indent=2) + "\n")
    manifest = corpus / "manifest.json"
    data = json.loads(manifest.read_text())
    data["files"][name] = digest
    data["files"]["source-provenance.json"] = hashlib.sha256(
        provenance.read_bytes()
    ).hexdigest()
    manifest.write_text(json.dumps(data, indent=2) + "\n")
    (corpus / "SHA256SUMS").write_text(
        "".join(f"{value}  {path}\n" for path, value in sorted(data["files"].items()))
    )


class SendPathReplay:
    """Reject altered copies of the frozen send-path corpus."""

    # collected although the name does not match python_classes: it is a golden key
    __test__ = True

    @pytest.fixture(autouse=True)
    def setUp(self, tmp_path: Path) -> None:
        """Copy the retained corpus into a fresh temporary directory for a test."""
        self.corpus = tmp_path / "corpus"
        shutil.copytree(CORPUS, self.corpus)

    def alter_oracle_code(self, address: str, before: str, after: str) -> None:
        """Replace a fragment of an oracle function in the copy and reseal it.

        Parameters
        ----------
        address : str
            The address of the function whose code is altered.
        before : str
            The fragment to replace; it must occur in the code.
        after : str
            The replacement text.
        """
        name = "oracle/c41-report.json"
        path = self.corpus / name
        report = json.loads(path.read_text())
        query = next(q for q in report["queries"] if q["label"] == address)
        code = query["result"]["structuredContent"]["code"]
        assert before in code, "the fragment to alter is absent from the code"
        query["result"]["structuredContent"]["code"] = code.replace(before, after)
        path.write_text(json.dumps(report, indent=2) + "\n")
        reseal(self.corpus, name)

    def test_frozen_corpus(self) -> None:
        """The retained corpus verifies as it was recorded."""
        verify(self.corpus)

    def test_rehashed_counter_without_node_difference(self) -> None:
        """A rehashed pending-byte counter without the node difference is rejected."""
        self.alter_oracle_code("10071650", "puVar3[3] - puVar3[2]", "puVar3[3]")
        with pytest.raises(ValueError, match="Pending byte count"):
            verify(self.corpus)

    def test_rehashed_negative_send_without_queueing(self) -> None:
        """A rehashed partial send that no longer queues the remainder is rejected."""
        self.alter_oracle_code(
            "10070d20", "*(int *)(param_1 + 0x3c) = param_2 + -0x10", "uVar2 = 0"
        )
        with pytest.raises(ValueError, match="Partial send queue"):
            verify(self.corpus)

    def test_rehashed_unconditional_callback(self) -> None:
        """A rehashed callback that always fires is rejected."""
        self.alter_oracle_code("10071770", "if (bVar1)", "if (true)")
        with pytest.raises(ValueError, match="Callback condition"):
            verify(self.corpus)

    def test_rehashed_forged_binary_identity(self) -> None:
        """A rehashed C40 report with a forged binary digest is rejected."""
        name = "oracle/c40-report.json"
        path = self.corpus / name
        report = json.loads(path.read_text())
        report["binary_sha256"] = "0" * 64
        path.write_text(json.dumps(report, indent=2) + "\n")
        reseal(self.corpus, name)
        with pytest.raises(ValueError, match="C40 binary hash"):
            verify(self.corpus)
