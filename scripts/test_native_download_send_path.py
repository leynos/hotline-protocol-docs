"""Fault controls for the frozen send-path replay."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_download_send_path import verify

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-download-send-path-01"
)


def reseal(corpus: Path, name: str) -> None:
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


class SendPathReplay(unittest.TestCase):
    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.corpus = Path(self.temp.name) / "corpus"
        shutil.copytree(CORPUS, self.corpus)

    def alter_oracle_code(self, address: str, before: str, after: str) -> None:
        name = "oracle/c41-report.json"
        path = self.corpus / name
        report = json.loads(path.read_text())
        query = next(q for q in report["queries"] if q["label"] == address)
        code = query["result"]["structuredContent"]["code"]
        self.assertIn(before, code)
        query["result"]["structuredContent"]["code"] = code.replace(before, after)
        path.write_text(json.dumps(report, indent=2) + "\n")
        reseal(self.corpus, name)

    def test_frozen_corpus(self) -> None:
        verify(self.corpus)

    def test_rehashed_counter_without_node_difference(self) -> None:
        self.alter_oracle_code("10071650", "puVar3[3] - puVar3[2]", "puVar3[3]")
        with self.assertRaisesRegex(ValueError, "Pending byte count"):
            verify(self.corpus)

    def test_rehashed_negative_send_without_queueing(self) -> None:
        self.alter_oracle_code(
            "10070d20", "*(int *)(param_1 + 0x3c) = param_2 + -0x10", "uVar2 = 0"
        )
        with self.assertRaisesRegex(ValueError, "Partial send queue"):
            verify(self.corpus)

    def test_rehashed_unconditional_callback(self) -> None:
        self.alter_oracle_code("10071770", "if (bVar1)", "if (true)")
        with self.assertRaisesRegex(ValueError, "Callback condition"):
            verify(self.corpus)

    def test_rehashed_forged_binary_identity(self) -> None:
        name = "oracle/c40-report.json"
        path = self.corpus / name
        report = json.loads(path.read_text())
        report["binary_sha256"] = "0" * 64
        path.write_text(json.dumps(report, indent=2) + "\n")
        reseal(self.corpus, name)
        with self.assertRaisesRegex(ValueError, "C40 binary hash"):
            verify(self.corpus)


if __name__ == "__main__":
    unittest.main()
