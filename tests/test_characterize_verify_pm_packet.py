"""Characterize ``verify_native_pm_packet`` before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. The retained
corpus is verified read-only; faults are made in a linked, resealed copy
(``pm_corpus_support``) so that each check can be reached, and pairs of faults
pin which error is raised first. The usage text of the command line is not
pinned, only its exit status.
"""

import hashlib
import json
import sys
import typing as typ

import pytest
import verify_native_pm_packet as verifier
from pm_corpus_support import BATCH, PmCorpus, dumps, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

CHARACTERIZES = "verify_native_pm_packet.py"
RESULT_FINGERPRINT = "5e2342cc84e05f4fff8ff47c7b1fa56f84a84eaae276b9b6fea783f28ce82597"
STATUS = "verified-bounded-native-pm"
RESULT_KEYS = ["status", "preflight", "postflight", "pm", "packet_connections"]
ZEROS = "0" * 64


def refused(root: Path, message: str) -> None:
    """Require that verifying ``root`` raises a ``ValueError`` matching ``^message``."""
    with pytest.raises(ValueError, match=f"^{message}"):
        verifier.verify(root)


@pytest.fixture
def corpus(tmp_path: Path) -> PmCorpus:
    """Link the retained corpus below a scratch directory.

    Returns
    -------
    PmCorpus
        The linked corpus.
    """
    return PmCorpus(tmp_path)


def fail_status(corpus: PmCorpus, label: str) -> None:
    """Mark a capture's report as failed, so its readback is incomplete."""
    report = corpus.read_json(f"{label}/report.json")
    report["status"] = "failed"
    corpus.reseal_capture(label, report=dumps(report))


class RetainedCorpusTests:
    """The retained corpus verifies, read-only."""

    def test_the_result_is_the_pinned_document(self) -> None:
        """Keys in order and the whole result, by fingerprint."""
        result = verifier.verify(BATCH)
        assert list(result) == RESULT_KEYS, "expected the result keys in order"
        assert result["status"] == STATUS, "expected the verified status"
        digest = hashlib.sha256(json.dumps(result).encode()).hexdigest()
        assert digest == RESULT_FINGERPRINT, "expected the pinned result"

    def test_the_parts_of_the_result_are_the_pinned_summaries(self) -> None:
        """Both readbacks, the semantic result and the packet connections."""
        result = verifier.verify(BATCH)
        assert result["preflight"]["uid_hex"] == "002a", "expected the preflight UID"
        assert result["postflight"]["uid_hex"] == "002d", "expected the postflight UID"
        assert (
            result["preflight"]["data_sha256"] == result["postflight"]["data_sha256"]
        ), "expected: both readbacks, the semantic result and the packet connections"
        assert result["preflight"]["files"] == 41, "expected 41 files"
        assert result["preflight"]["accounts"] == 2, "expected two accounts"
        expected = {
            "preflight": ["a", "download"],
            "observe": ["main", "peer"],
            "postflight": ["a", "download"],
        }
        assert result["packet_connections"] == expected, "expected the connections"

    def test_a_relinked_unaltered_corpus_verifies(self, corpus: PmCorpus) -> None:
        """Linking and resealing without a change does not change the result."""
        result = verifier.verify(corpus.seal())
        assert result == verifier.verify(BATCH), "expected the same result"


class InventoryTests:
    """The manifest and checksum list are checked before any capture."""

    def test_another_manifest_status_is_refused(self, corpus: PmCorpus) -> None:
        """The status must be the bounded PM one."""
        corpus.manifest["status"] = "other"
        refused(corpus.seal(), "PM manifest status differs$")

    def test_a_file_that_does_not_match_its_recorded_hash_is_named(
        self, corpus: PmCorpus
    ) -> None:
        """The manifest's hash is compared with the bytes."""
        corpus.overwrite("tcpdump.log", b"changed")
        refused(corpus.seal(), "PM file hash differs: tcpdump.log$")

    def test_a_checksum_list_that_omits_a_file_is_refused(
        self, corpus: PmCorpus
    ) -> None:
        """The list must name every manifest file and the manifest."""
        root = corpus.seal()
        lines = (root / "SHA256SUMS").read_text().splitlines()
        (root / "SHA256SUMS").write_text("\n".join(lines[1:]) + "\n")
        refused(root, "PM SHA inventory differs$")

    def test_a_checksum_line_with_another_hash_is_named(self, corpus: PmCorpus) -> None:
        """Each line's hash is compared with its file."""
        root = corpus.seal()
        lines = (root / "SHA256SUMS").read_text().splitlines()
        path = lines[0].split("  ", 1)[1]
        lines[0] = f"{ZEROS}  {path}"
        (root / "SHA256SUMS").write_text("\n".join(lines) + "\n")
        refused(root, f"PM SHA line differs: {path}$")

    def test_the_status_check_comes_before_the_file_hashes(
        self, corpus: PmCorpus
    ) -> None:
        """A wrong status with a changed file is a status error."""
        corpus.manifest["status"] = "other"
        corpus.overwrite("tcpdump.log", b"changed")
        refused(corpus.seal(), "PM manifest status differs$")

    def test_the_file_hashes_come_before_the_checksum_list(
        self, corpus: PmCorpus
    ) -> None:
        """A changed file with a short checksum list is a file error."""
        corpus.overwrite("tcpdump.log", b"changed")
        root = corpus.seal()
        lines = (root / "SHA256SUMS").read_text().splitlines()
        (root / "SHA256SUMS").write_text("\n".join(lines[1:]) + "\n")
        refused(root, "PM file hash differs: tcpdump.log$")

    def test_the_list_inventory_comes_before_the_line_hashes(
        self, corpus: PmCorpus
    ) -> None:
        """A short list with a wrong line is an inventory error."""
        root = corpus.seal()
        lines = (root / "SHA256SUMS").read_text().splitlines()
        lines[1] = f"{ZEROS}  {lines[1].split('  ', 1)[1]}"
        (root / "SHA256SUMS").write_text("\n".join([*lines[1:]]) + "\n")
        refused(root, "PM SHA inventory differs$")

    def test_a_missing_manifest_is_a_file_not_found_error(self, tmp_path: Path) -> None:
        """An empty directory has no manifest."""
        with pytest.raises(FileNotFoundError):
            verifier.verify(tmp_path)


class ReadbackTests:
    """The two full readbacks, preflight first."""

    def test_a_capture_whose_checksum_list_is_stale_is_refused_by_the_capture_check(
        self, corpus: PmCorpus
    ) -> None:
        """The capture's own verification runs before the readback checks."""
        report = corpus.read_json("preflight/report.json")
        report["status"] = "failed"
        corpus.replace("preflight/report.json", dumps(report))
        refused(corpus.seal(), "Checksum mismatch: report.json$")

    def test_a_plan_that_is_not_the_baseline_is_refused(self, corpus: PmCorpus) -> None:
        """The capture's plan bytes must hash to the baseline's."""
        plan = json.dumps(corpus.read_json("preflight/plan.json")).encode()
        report = corpus.read_json("preflight/report.json")
        report["plan_sha256"] = sha(plan)
        corpus.reseal_capture("preflight", plan=plan, report=dumps(report))
        refused(corpus.seal(), "preflight: A7 plan differs$")

    def test_an_incomplete_sequence_is_refused(self, corpus: PmCorpus) -> None:
        """A failed report is not a full readback."""
        fail_status(corpus, "postflight")
        refused(corpus.seal(), "postflight: full A7 sequence incomplete$")

    def test_the_plan_check_comes_before_the_sequence_check(
        self, corpus: PmCorpus
    ) -> None:
        """A plan that differs and a failed report is a plan error."""
        plan = json.dumps(corpus.read_json("preflight/plan.json")).encode()
        report = corpus.read_json("preflight/report.json")
        report["plan_sha256"] = sha(plan)
        report["status"] = "failed"
        corpus.reseal_capture("preflight", plan=plan, report=dumps(report))
        refused(corpus.seal(), "preflight: A7 plan differs$")

    def test_preflight_is_reported_before_postflight(self, corpus: PmCorpus) -> None:
        """When both captures are incomplete, the preflight is named."""
        fail_status(corpus, "preflight")
        fail_status(corpus, "postflight")
        refused(corpus.seal(), "preflight: full A7 sequence incomplete$")

    def test_a_baseline_reply_that_differs_from_the_source_is_refused(
        self, corpus: PmCorpus
    ) -> None:
        """The source report is the reference for replies 10 to 12."""
        source = corpus.read_json("a7-report.json")
        frame = next(
            f
            for f in source["frames"]
            if f["is_reply"] and f["id"] == 10 and f["connection"] == "a"
        )
        frame["fields"][0]["hex"] = "ff"
        corpus.replace("a7-report.json", dumps(source))
        refused(corpus.seal(), "preflight: baseline reply 10 differs$")

    def test_the_readbacks_come_before_the_message_checks(
        self, corpus: PmCorpus
    ) -> None:
        """An incomplete readback hides a wrong semantic receipt."""
        fail_status(corpus, "postflight")
        receipt = corpus.read_json("observe-semantic.json")
        receipt["main_uid_hex"] = "0000"
        corpus.replace("observe-semantic.json", dumps(receipt))
        refused(corpus.seal(), "postflight: full A7 sequence incomplete$")


class MessageAndPacketTests:
    """The message semantics, then the packet views."""

    def test_a_semantic_receipt_that_differs_is_refused(self, corpus: PmCorpus) -> None:
        """The saved receipt must equal the recomputed one."""
        receipt = corpus.read_json("observe-semantic.json")
        receipt["main_uid_hex"] = "0000"
        corpus.replace("observe-semantic.json", dumps(receipt))
        refused(corpus.seal(), "PM semantic receipt differs$")

    def test_a_packet_reconciliation_that_differs_is_refused(
        self, corpus: PmCorpus
    ) -> None:
        """The saved reconciliation must equal the observed one."""
        saved = corpus.read_json("packet-reconciliation.json")
        saved["observe"]["status"] = "other"
        corpus.replace("packet-reconciliation.json", dumps(saved))
        refused(corpus.seal(), "Saved PM packet reconciliation differs$")

    def test_a_final_host_capture_that_is_not_the_last_snapshot_is_refused(
        self, corpus: PmCorpus
    ) -> None:
        """The final host capture must equal the postflight snapshot."""
        final = corpus.large_file("host")
        data = (corpus.root / final).read_bytes()
        corpus.replace(final, data + b"x")
        refused(corpus.seal(), "Final host capture differs$")

    def test_the_semantic_check_comes_before_the_packet_checks(
        self, corpus: PmCorpus
    ) -> None:
        """A wrong receipt and a wrong reconciliation is a receipt error."""
        receipt = corpus.read_json("observe-semantic.json")
        receipt["main_uid_hex"] = "0000"
        corpus.replace("observe-semantic.json", dumps(receipt))
        saved = corpus.read_json("packet-reconciliation.json")
        saved["observe"]["status"] = "other"
        corpus.replace("packet-reconciliation.json", dumps(saved))
        refused(corpus.seal(), "PM semantic receipt differs$")

    def test_the_reconciliation_comes_before_the_final_capture(
        self, corpus: PmCorpus
    ) -> None:
        """A wrong reconciliation and final capture is a reconciliation error."""
        saved = corpus.read_json("packet-reconciliation.json")
        saved["observe"]["status"] = "other"
        corpus.replace("packet-reconciliation.json", dumps(saved))
        final = corpus.large_file("host")
        corpus.replace(final, (corpus.root / final).read_bytes() + b"x")
        refused(corpus.seal(), "Saved PM packet reconciliation differs$")


class CommandLineTests:
    """``main`` reads the corpus path and an optional output path."""

    @staticmethod
    def argv(monkeypatch: pytest.MonkeyPatch, *arguments: object) -> None:
        """Set the command line of a run."""
        arguments_text = [str(argument) for argument in arguments]
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *arguments_text])

    def test_the_status_is_printed(
        self, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
    ) -> None:
        """A verified corpus prints its status on one line."""
        self.argv(monkeypatch, BATCH)
        verifier.main()
        assert capsys.readouterr().out == f"{STATUS}\n", "expected the status line"

    def test_an_output_file_receives_the_result_as_indented_json(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The result is written with two-space indentation and a final newline."""
        output = tmp_path / "result.json"
        self.argv(monkeypatch, BATCH, "--output", output)
        verifier.main()
        expected = json.dumps(verifier.verify(BATCH), indent=2) + "\n"
        assert output.read_text() == expected, "expected the written result"

    def test_an_existing_output_is_refused_after_a_successful_verification(
        self,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        capsys: pytest.CaptureFixture[str],
    ) -> None:
        """Exit status 2, the file untouched and no status line."""
        output = tmp_path / "result.json"
        output.write_text("kept")
        self.argv(monkeypatch, BATCH, "--output", output)
        with pytest.raises(SystemExit) as caught:
            verifier.main()
        assert caught.value.code == 2, "expected the usage status"
        assert output.read_text() == "kept", "expected the file untouched"
        assert not capsys.readouterr().out, "expected no status line"

    def test_a_refused_corpus_is_reported_before_an_existing_output(
        self, monkeypatch: pytest.MonkeyPatch, corpus: PmCorpus, tmp_path: Path
    ) -> None:
        """Verification runs first, so its error wins."""
        corpus.manifest["status"] = "other"
        output = tmp_path / "result.json"
        output.write_text("kept")
        self.argv(monkeypatch, corpus.seal(), "--output", output)
        with pytest.raises(ValueError, match="PM manifest status differs"):
            verifier.main()

    def test_no_corpus_argument_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The corpus path is required."""
        self.argv(monkeypatch)
        with pytest.raises(SystemExit) as caught:
            verifier.main()
        assert caught.value.code == 2, "expected the usage status"
