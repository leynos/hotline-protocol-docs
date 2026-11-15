"""Fault controls for the portable option-one native ban corpus."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_ban_one import verify

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-ban-one-01"
)


class BanOneTests(unittest.TestCase):
    def setUp(self) -> None:
        self.temporary = tempfile.TemporaryDirectory()
        self.addCleanup(self.temporary.cleanup)
        mothra = Path(self.temporary.name) / "mothra"
        self.corpus = mothra / "evidence/gap-remediation/2026-11-13/native-ban-one-01"
        self.corpus.parent.mkdir(parents=True)
        shutil.copytree(CORPUS, self.corpus)
        reference = (
            mothra
            / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
        )
        reference.mkdir(parents=True)
        original = (
            CORPUS.parents[3]
            / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
        )
        for suffix in ("data", "rsrc"):
            shutil.copyfile(
                original / f"mothra-race-fixture.{suffix}",
                reference / f"mothra-race-fixture.{suffix}",
            )

    def rehash(self, relative: str) -> None:
        manifest = json.loads((self.corpus / "manifest.json").read_text())
        manifest["files"][relative] = hashlib.sha256(
            (self.corpus / relative).read_bytes()
        ).hexdigest()
        (self.corpus / "manifest.json").write_text(
            json.dumps(manifest, indent=2) + "\n"
        )
        (self.corpus / "SHA256SUMS").write_text(
            "".join(
                f"{sha}  {name}\n" for name, sha in sorted(manifest["files"].items())
            )
        )

    def test_frozen_corpus(self) -> None:
        self.assertEqual(verify(CORPUS)["status"], "verified_option_one_notice_only")

    def test_rehashed_probe_cannot_be_recast_as_completed(self) -> None:
        relative = "fixture/probe-capture/report.json"
        report = json.loads((self.corpus / relative).read_text())
        report.update(status="completed", completed_actions=4, error="")
        (self.corpus / relative).write_text(json.dumps(report, indent=2) + "\n")
        checksums = self.corpus / "fixture/probe-capture/checksums.sha256"
        checksums.write_text(
            "".join(
                f"{hashlib.sha256((checksums.parent / name).read_bytes()).hexdigest()}  {name}\n"
                for name in ("plan.json", "report.json")
            )
        )
        self.rehash(relative)
        self.rehash("fixture/probe-capture/checksums.sha256")
        with self.assertRaisesRegex(ValueError, "Probe failure was recast"):
            verify(self.corpus)

    def test_rehashed_spoofed_302_uid_fails(self) -> None:
        relative = "fixture/ban-stream-views.json"
        views = json.loads((self.corpus / relative).read_text())
        views["namespace"]["main"]["frames"][-1]["fields"][0]["hex"] = "ffff"
        (self.corpus / relative).write_text(json.dumps(views, indent=2) + "\n")
        self.rehash(relative)
        with self.assertRaisesRegex(ValueError, "Frozen ACK/302 view differs"):
            verify(self.corpus)

    def test_rehashed_truncated_packet_fails(self) -> None:
        relative = "boot/lab-namespace.pcap"
        path = self.corpus / relative
        path.write_bytes(path.read_bytes()[:-1])
        self.rehash(relative)
        with self.assertRaisesRegex(ValueError, "Truncated packet bytes"):
            verify(self.corpus)


if __name__ == "__main__":
    unittest.main()
