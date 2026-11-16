"""Reject changed identities, caller sets and stored field boundaries."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from verify_account_attribute import decode_record, verify

# scripts/tests sits two levels below the repository root that holds evidence/.
ROOT = Path(__file__).resolve().parents[2]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-13/account-attribute-01"
PREFIX = Path("evidence/gap-remediation/2026-11-13/account-attribute-01")


def rewrite_sums(corpus: Path) -> None:
    """Rewrite the checksum file of an edited copy so only the edit is judged."""
    lines = []
    for path in sorted(corpus.rglob("*")):
        if path.is_file() and path.name != "SHA256SUMS":
            digest = hashlib.sha256(path.read_bytes()).hexdigest()
            lines.append(f"{digest}  {PREFIX / path.relative_to(corpus)}\n")
    (corpus / "SHA256SUMS").write_text("".join(lines))


def changed_copy(tmp_path: Path) -> Path:
    """Copy the frozen trace into a fresh directory for one edit.

    Returns
    -------
    pathlib.Path
        The copy, which the test may change.
    """
    corpus = tmp_path / "corpus"
    shutil.copytree(CORPUS, corpus)
    return corpus


class AccountAttributeEvidenceTests:
    """Reject changed oracle identity, caller sets and stored boundaries."""

    def test_frozen_oracle_and_stored_records_verify(self) -> None:
        """The frozen trace verifies with its recorded query and caller counts."""
        result = verify(CORPUS, ROOT)
        assert result["query_count"] == 28, "the query count differs"
        assert result["reader_direct_callers"] == 10, "the reader count differs"
        assert result["writer_direct_callers"] == 2, "the writer count differs"
        assert result["creator_direct_callers"] == 3, "the creator count differs"

    def test_wrong_oracle_identity_rejected_with_new_checksums(
        self, tmp_path: Path
    ) -> None:
        """A changed oracle program digest is rejected with fresh checksums."""
        corpus = changed_copy(tmp_path)
        path = corpus / "queries/AA-C-100073c0.json"
        record = json.loads(path.read_text())
        record["program"]["sha256"] = "0" * 64
        path.write_text(json.dumps(record))
        rewrite_sums(corpus)
        with pytest.raises(ValueError, match="oracle identity"):
            verify(corpus, ROOT)

    def test_omitted_reader_consumer_rejected_with_new_checksums(
        self, tmp_path: Path
    ) -> None:
        """An omitted reader caller is rejected with fresh checksums."""
        corpus = changed_copy(tmp_path)
        path = corpus / "queries/AA-C-100073c0.json"
        record = json.loads(path.read_text())
        callers = record["result"]["structuredContent"]["callers"]
        callers["items"].pop()
        callers["total"] -= 1
        path.write_text(json.dumps(record))
        rewrite_sums(corpus)
        with pytest.raises(ValueError, match="reader caller set"):
            verify(corpus, ROOT)

    def test_stored_length_cannot_cross_next_field(self) -> None:
        """A length word beyond the 64-byte slot is rejected."""
        source = (
            ROOT / "evidence/gap-remediation/2026-11-12/native-core-01/"
            "account111-value/UserData.bin"
        )
        record = bytearray(source.read_bytes())
        record[0x254:0x256] = (65).to_bytes(2, "big")
        with pytest.raises(ValueError, match="attribute length"):
            decode_record(bytes(record))

    def test_whole_record_copy_not_mistaken_for_no_consumer(
        self, tmp_path: Path
    ) -> None:
        """A removed whole-record copy in the admin update is rejected."""
        corpus = changed_copy(tmp_path)
        path = corpus / "queries/AA-D-10007780.json"
        record = json.loads(path.read_text())
        code = record["result"]["structuredContent"]["code"]
        old = "FUN_1002c440(uVar2,0,local_300,0x2de,0);"
        assert old in code, "the recorded whole-record copy is absent"
        changed = code.replace(old, "/* omitted whole-record write */", 1)
        record["result"]["structuredContent"]["code"] = changed
        path.write_text(json.dumps(record))
        path.with_suffix(".c").write_text(changed)
        rewrite_sums(corpus)
        with pytest.raises(ValueError, match="whole account record"):
            verify(corpus, ROOT)
