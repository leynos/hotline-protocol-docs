"""Reject changed identities, caller sets and stored field boundaries."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_account_attribute import decode_record, verify

ROOT = Path(__file__).resolve().parents[2] / "mothra"
CORPUS = ROOT / "evidence/gap-remediation/2026-11-13/account-attribute-01"
PREFIX = Path("evidence/gap-remediation/2026-11-13/account-attribute-01")


def rewrite_sums(corpus: Path) -> None:
    (corpus / "SHA256SUMS").write_text(
        "".join(
            f"{hashlib.sha256(path.read_bytes()).hexdigest()}  {PREFIX / path.relative_to(corpus)}\n"
            for path in sorted(corpus.rglob("*"))
            if path.is_file() and path.name != "SHA256SUMS"
        )
    )


class AccountAttributeEvidenceTests(unittest.TestCase):
    def test_frozen_oracle_and_stored_records_verify(self) -> None:
        result = verify(CORPUS, ROOT)
        self.assertEqual(result["query_count"], 28)
        self.assertEqual(result["reader_direct_callers"], 10)
        self.assertEqual(result["writer_direct_callers"], 2)
        self.assertEqual(result["creator_direct_callers"], 3)

    def test_wrong_oracle_identity_rejected_with_new_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            shutil.copytree(CORPUS, corpus)
            path = corpus / "queries/AA-C-100073c0.json"
            record = json.loads(path.read_text())
            record["program"]["sha256"] = "0" * 64
            path.write_text(json.dumps(record))
            rewrite_sums(corpus)
            with self.assertRaisesRegex(ValueError, "oracle identity"):
                verify(corpus, ROOT)

    def test_omitted_reader_consumer_rejected_with_new_checksums(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            shutil.copytree(CORPUS, corpus)
            path = corpus / "queries/AA-C-100073c0.json"
            record = json.loads(path.read_text())
            callers = record["result"]["structuredContent"]["callers"]
            callers["items"].pop()
            callers["total"] -= 1
            path.write_text(json.dumps(record))
            rewrite_sums(corpus)
            with self.assertRaisesRegex(ValueError, "reader caller set"):
                verify(corpus, ROOT)

    def test_stored_length_cannot_cross_next_field(self) -> None:
        source = (
            ROOT
            / "evidence/gap-remediation/2026-11-12/native-core-01/account111-value/UserData.bin"
        )
        record = bytearray(source.read_bytes())
        record[0x254:0x256] = (65).to_bytes(2, "big")
        with self.assertRaisesRegex(ValueError, "attribute length"):
            decode_record(bytes(record))

    def test_whole_record_copy_not_mistaken_for_no_consumer(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(temporary) / "corpus"
            shutil.copytree(CORPUS, corpus)
            path = corpus / "queries/AA-D-10007780.json"
            record = json.loads(path.read_text())
            code = record["result"]["structuredContent"]["code"]
            old = "FUN_1002c440(uVar2,0,local_300,0x2de,0);"
            self.assertIn(old, code)
            changed = code.replace(old, "/* omitted whole-record write */", 1)
            record["result"]["structuredContent"]["code"] = changed
            path.write_text(json.dumps(record))
            path.with_suffix(".c").write_text(changed)
            rewrite_sums(corpus)
            with self.assertRaisesRegex(ValueError, "whole account record"):
                verify(corpus, ROOT)
