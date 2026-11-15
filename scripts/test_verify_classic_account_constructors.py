"""Fault controls for the retained Classic account-constructor proof."""

import copy
import unittest

from scripts.verify_classic_account_constructors import ROOT, load_evidence, verify


class ClassicAccountConstructorsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.original = load_evidence()
        cls.server = (
            ROOT / "evidence/hotline-server-1.9/queries/D-10015500.c"
        ).read_text()

    def setUp(self) -> None:
        self.bundle = copy.deepcopy(self.original)

    def query(self, batch: str, address: str) -> dict:
        if batch == "b37-followup":
            queries = self.bundle[batch]["queries"]
        else:
            queries = [q for run in self.bundle[batch]["runs"] for q in run["queries"]]
        return next(
            q
            for q in queries
            if q["tool"] == "decompile_function_by_address"
            and q["arguments"]["address"] == address
        )

    def test_retained_evidence_passes(self) -> None:
        self.assertEqual(
            verify(self.bundle, self.server)["status"],
            "verified-bounded-constructor-trace",
        )

    def test_wrong_direct_field_rejected_for_both_constructors(self) -> None:
        for batch, address, operation in (
            ("b37-followup", "1000c210", "350"),
            ("b38-report", "1000c800", "353"),
        ):
            with self.subTest(operation=operation):
                bad = copy.deepcopy(self.original)
                self.bundle = bad
                query = self.query(batch, address)
                source = query["result"]["structuredContent"]["code"]
                query["result"]["structuredContent"]["code"] = source.replace(
                    "FUN_100b05d0(param_1[2],0x6e,",
                    "FUN_100b05d0(param_1[2],0x6f,",
                    1,
                )
                with self.assertRaisesRegex(
                    ValueError, f"{operation} direct field list"
                ):
                    verify(bad, self.server)

    def test_wrong_nested_field_and_conditional_rejected(self) -> None:
        query = self.query("b39-report", "1005b5b0")
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            "FUN_100b05d0(local_114,0x6e,",
            "FUN_100b05d0(local_114,0x6f,",
            1,
        )
        with self.assertRaisesRegex(ValueError, "349 nested field list"):
            verify(self.bundle, self.server)
        query["result"]["structuredContent"]["code"] = source.replace(
            "cVar6 = FUN_1005e650(local_118);", "cVar6 = 1;", 1
        )
        with self.assertRaisesRegex(ValueError, "conditional old-login"):
            verify(self.bundle, self.server)

    def test_wrong_old_login_only_list_rejected(self) -> None:
        query = self.query("b39-report", "1005ce30")
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            "FUN_100b05d0(uVar3,0x65,", "FUN_100b05d0(uVar3,0x69,", 1
        )
        with self.assertRaisesRegex(ValueError, "old-login-only list"):
            verify(self.bundle, self.server)

    def test_changed_counted_tlv_builder_rejected(self) -> None:
        query = self.query("b39-report", "100b05d0")
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            "puVar2[2] = (short)param_4", "puVar2[2] = 0", 1
        )
        with self.assertRaisesRegex(ValueError, "counted BE16 TLV append"):
            verify(self.bundle, self.server)

    def test_error_code_cannot_be_relabelled_as_field(self) -> None:
        query = next(
            q
            for q in self.bundle["b37-report"]["records"]
            if q["label"] == "field111-a-decompile"
        )
        source = query["result"]["structuredContent"]["code"]
        query["result"]["structuredContent"]["code"] = source.replace(
            "FUN_1007d7e0(8,0x6f)", "FUN_100b05d0(p,0x6f,v,n)", 1
        )
        with self.assertRaisesRegex(ValueError, "not the retained error path"):
            verify(self.bundle, self.server)

    def test_identity_and_server_deletion_branch_required(self) -> None:
        run = self.bundle["b38-report"]["runs"][0]
        run["queries"][-1]["result"]["structuredContent"]["sha256"] = "0" * 64
        with self.assertRaisesRegex(ValueError, "program identity changed"):
            verify(self.bundle, self.server)
        self.bundle = copy.deepcopy(self.original)
        altered = self.server.replace(
            "if ((local_3e0 == 0) && (local_358 == 0))", "if (false)", 1
        )
        with self.assertRaisesRegex(ValueError, "server 349 deletion branch"):
            verify(self.bundle, altered)


if __name__ == "__main__":
    unittest.main()
