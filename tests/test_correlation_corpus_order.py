"""Pin the order of the ID verifier's oracle and corpus checks.

The goldens observe only the retained corpus, so the order in which an unsound
corpus is refused is held here, outside ``scripts/tests``, whose tests are the
golden keys. Every expectation was observed on the version of the scripts
before ``verify`` and ``verify_oracle`` were split into smaller functions
(commit 8b4c3df).
"""

import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from verify_native_correlation import verify, verify_oracle

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Report = dict[str, typ.Any]

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-12/native-correlation-01"
)


class OracleOrderTests:
    """Keep the oracle checks in the order in which they have always run."""

    @staticmethod
    def copy_oracle(tmp_path: Path) -> Path:
        """Copy the oracle queries and their lists so that they can be broken.

        Returns
        -------
        pathlib.Path
            The copy of the corpus directory.
        """
        shutil.copytree(BATCH / "oracle-queries", tmp_path / "oracle-queries")
        for path in BATCH.glob("oracle-*.json"):
            shutil.copy2(path, tmp_path / path.name)
        return tmp_path

    @staticmethod
    def queries(directory: Path) -> list[Report]:
        """List the queries in the order that the verifier reads them.

        Returns
        -------
        list[dict[str, typing.Any]]
            The query descriptions.
        """
        return [
            q
            for p in directory.glob("oracle-*.json")
            for q in json.loads(p.read_text())
        ]

    @staticmethod
    def edit(
        directory: Path, query: Report, change: cabc.Callable[[Report], None]
    ) -> None:
        """Apply ``change`` to the retained record of ``query``."""
        path = directory / "oracle-queries" / (query["id"] + ".json")
        record = json.loads(path.read_text())
        change(record)
        path.write_text(json.dumps(record))

    def test_the_inventory_precedes_the_identities(self, tmp_path: Path) -> None:
        """A missing query is reported although a record has another identity."""
        directory = self.copy_oracle(tmp_path)
        first = self.queries(directory)[0]
        self.edit(directory, first, lambda r: r["program"].update(sha256="0" * 64))
        path = next(directory.glob("oracle-*.json"))
        path.write_text(json.dumps(json.loads(path.read_text())[1:]))
        with pytest.raises(ValueError, match="ID oracle query inventory differs"):
            verify_oracle(directory)

    def test_the_identity_precedes_the_outcome(self, tmp_path: Path) -> None:
        """A wrong identity is reported although the outcome flag is wrong too."""
        directory = self.copy_oracle(tmp_path)
        first = self.queries(directory)[0]

        def change(record: Report) -> None:
            """Change the program identity and flip the error flag."""
            record["program"]["sha256"] = "0" * 64
            record["result"]["isError"] = not record["result"]["isError"]

        self.edit(directory, first, change)
        with pytest.raises(ValueError, match="ID oracle identity differs"):
            verify_oracle(directory)

    def test_the_outcome_precedes_the_code(self, tmp_path: Path) -> None:
        """A wrong outcome flag is reported although the retained code is wrong."""
        directory = self.copy_oracle(tmp_path)
        queries = self.queries(directory)
        with_code = next(
            q
            for q in queries
            if (directory / "oracle-queries" / (q["id"] + ".c")).exists()
        )

        def change(record: Report) -> None:
            """Flip the error flag."""
            record["result"]["isError"] = not record["result"]["isError"]

        self.edit(directory, with_code, change)
        code = directory / "oracle-queries" / (with_code["id"] + ".c")
        code.write_text(code.read_text() + "changed")
        with pytest.raises(ValueError, match="Exploratory function-query outcome"):
            verify_oracle(directory)

    def test_the_queries_precede_the_lifecycle_functions(self, tmp_path: Path) -> None:
        """A changed record is reported although a lifecycle function differs."""
        directory = self.copy_oracle(tmp_path)
        first = self.queries(directory)[0]
        self.edit(directory, first, lambda r: r["program"].update(sha256="0" * 64))
        lifecycle = directory / "oracle-queries/ID-D-10058090.c"
        lifecycle.write_text("changed")
        with pytest.raises(ValueError, match="ID oracle identity differs"):
            verify_oracle(directory)

    def test_the_lifecycle_functions_precede_the_instructions(
        self, tmp_path: Path
    ) -> None:
        """A changed function is reported although the increment bytes differ."""
        directory = self.copy_oracle(tmp_path)
        (directory / "oracle-queries/ID-D-10058090.c").write_text("changed")
        function = directory / "oracle-queries/ID-D-10058090.json"
        retained = json.loads(function.read_text())
        retained["result"]["structuredContent"]["code"] = "changed"
        function.write_text(json.dumps(retained))
        path = directory / "oracle-queries/ID-A-10058d70.json"
        record = json.loads(path.read_text())
        record["result"]["structuredContent"]["items"][1]["bytes"] = "00000000"
        path.write_text(json.dumps(record))
        with pytest.raises(ValueError, match="Lifecycle function identity differs"):
            verify_oracle(directory)


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
    def edit_manifest(directory: Path, **changes: object) -> None:
        """Replace keys of the manifest."""
        path = directory / "manifest.json"
        manifest = json.loads(path.read_text())
        manifest.update(changes)
        path.write_text(json.dumps(manifest))

    def test_the_case_inventory_precedes_the_corpus_identity(
        self, tmp_path: Path
    ) -> None:
        """A wrong case list is reported although the oracle hash is wrong."""
        directory = self.copy_corpus(tmp_path)
        self.edit_manifest(directory, cases=[], oracle_sha256="0" * 64)
        with pytest.raises(ValueError, match="ID case inventory differs"):
            verify(directory)

    def test_the_corpus_identity_precedes_the_packet_reads(
        self, tmp_path: Path
    ) -> None:
        """A wrong oracle hash is reported although the host capture is missing."""
        directory = self.copy_corpus(tmp_path)
        self.edit_manifest(directory, oracle_sha256="0" * 64)
        (directory / "host.pcap").unlink()
        with pytest.raises(ValueError, match="ID corpus identity differs"):
            verify(directory)

    def test_the_packet_reads_precede_the_driver_source(self, tmp_path: Path) -> None:
        """A missing host capture is reported although the driver copy is missing."""
        directory = self.copy_corpus(tmp_path)
        (directory / "host.pcap").unlink()
        (directory / "protocol_capture.py.as-run.txt").unlink()
        with pytest.raises(FileNotFoundError, match="host"):
            verify(directory)

    def test_the_plan_precedes_the_capture_verification(self, tmp_path: Path) -> None:
        """A changed plan is reported before the capture's integrity is checked."""
        directory = self.copy_corpus(tmp_path)
        path = directory / "transcripts/client-id-boundaries-and-reuse/plan.json"
        plan = json.loads(path.read_text())
        plan["steps"] = []
        path.write_text(json.dumps(plan))
        with pytest.raises(ValueError, match="ID preparation plan differs"):
            verify(directory)

    def test_the_reconciliation_precedes_the_oracle(self, tmp_path: Path) -> None:
        """A changed reconciliation is reported although an oracle record differs."""
        directory = self.copy_corpus(tmp_path)
        (directory / "packet-reconciliation.json").write_text("{}")
        (directory / "oracle-queries/ID-D-10058090.c").write_text("changed")
        with pytest.raises(ValueError, match="ID packet observations differ"):
            verify(directory)
