"""Pin the order of the identity verifier's corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before ``verify`` was split into smaller functions (commit 8b4c3df).
"""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_account_identity import verify

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-account-identity-01"
)
WRONG_HASH = "0" * 64
DROPPED = "1 packets dropped by kernel"


class CorpusOrderTests:
    """Keep the corpus-level checks in the order in which they have always run."""

    @staticmethod
    def copy_corpus(tmp_path: Path) -> Path:
        """Copy the retained corpus so that it can be broken.

        Returns
        -------
        pathlib.Path
            The copy.
        """
        directory = tmp_path / "fixtures"
        shutil.copytree(BATCH, directory)
        return directory

    @staticmethod
    def edit(directory: Path, name: str, **changes: object) -> None:
        """Replace keys of a JSON file of the corpus."""
        path = directory / name
        data = json.loads(path.read_text())
        data.update(changes)
        path.write_text(json.dumps(data))

    def test_the_report_inventory_precedes_the_packet_reads(
        self, tmp_path: Path
    ) -> None:
        """A wrong report list is reported although the host capture is missing."""
        directory = self.copy_corpus(tmp_path)
        self.edit(directory, "manifest.json", reports=[])
        (directory / "host.pcap").unlink()
        with pytest.raises(ValueError, match="Identity report inventory differs"):
            verify(directory)

    def test_the_packets_are_read_before_the_runtime(self, tmp_path: Path) -> None:
        """A missing guest capture is reported although the runtime is wrong."""
        directory = self.copy_corpus(tmp_path)
        (directory / "guest.pcap").unlink()
        self.edit(directory, "runtime.json", identity_observation={})
        with pytest.raises(FileNotFoundError, match="guest"):
            verify(directory)

    def test_the_runtime_precedes_the_recorder_count(self, tmp_path: Path) -> None:
        """A wrong runtime is reported although the recorder dropped packets."""
        directory = self.copy_corpus(tmp_path)
        self.edit(
            directory,
            "runtime.json",
            identity_observation={
                "running_executable_sha256": WRONG_HASH,
                "service_state": "",
            },
        )
        (directory / "host-capture-statistics.txt").write_text(DROPPED)
        with pytest.raises(ValueError, match="Identity runtime provenance differs"):
            verify(directory)

    def test_the_recorder_count_precedes_the_unread_tails(self, tmp_path: Path) -> None:
        """A wrong drop count is reported although the unread tails differ."""
        directory = self.copy_corpus(tmp_path)
        (directory / "host-capture-statistics.txt").write_text(DROPPED)
        (directory / "unread-tails.json").write_text("{}")
        with pytest.raises(ValueError, match="Identity recorder count or drops differ"):
            verify(directory)

    def test_the_unread_tails_precede_the_plans(self, tmp_path: Path) -> None:
        """Wrong unread cases are reported although the first plan differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "unread-tails.json").write_text("{}")
        self.edit(directory, "preflight/plan.json", steps=[])
        with pytest.raises(ValueError, match="Unread identity cases differ"):
            verify(directory)

    def test_the_plan_precedes_the_capture_verification(self, tmp_path: Path) -> None:
        """A changed plan is reported before the capture's integrity is checked."""
        directory = self.copy_corpus(tmp_path)
        self.edit(directory, "preflight/plan.json", steps=[])
        with pytest.raises(ValueError, match="Identity plan differs"):
            verify(directory)

    def test_the_packet_observations_precede_the_baseline(self, tmp_path: Path) -> None:
        """Changed packet observations are reported first of the later checks."""
        directory = self.copy_corpus(tmp_path)
        (directory / "packet-observations.json").write_text("{}")
        with pytest.raises(ValueError, match="Retained packet observations differ"):
            verify(directory)

    def test_the_as_run_sources_precede_the_oracle_queries(
        self, tmp_path: Path
    ) -> None:
        """A changed as-run source is reported although an oracle query is missing."""
        directory = self.copy_corpus(tmp_path)
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        name = "sources/native_packet_evidence.py.as-run.txt"
        manifest["as_run_sources"][name] = WRONG_HASH
        path.write_text(json.dumps(manifest))
        next((directory / "oracle-queries").glob("*.json")).unlink()
        with pytest.raises(ValueError, match="Identity as-run source changed"):
            verify(directory)
