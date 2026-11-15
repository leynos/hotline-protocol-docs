"""Reject password-placeholder, sparse-update and native record misreadings."""

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from verify_native_account_updates import account_reply, storage, verify
from verify_native_auth import reply
from verify_native_shx import fields

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-account-update-01"
)


class AccountUpdateTests(unittest.TestCase):
    def report(self, label: str) -> dict:
        return json.loads((BATCH / label / "report.json").read_text())

    def test_entire_paired_account_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual((result["positive_logins"], result["negative_logins"]), (9, 8))

    def test_sparse_update_clears_instead_of_preserving_access(self) -> None:
        frame = reply(self.report("mutation-sparse"), 12)
        next(f for f in frame["fields"] if f["id"] == 110)["hex"] = "2000000000000000"
        with self.assertRaisesRegex(ValueError, "default/placeholder"):
            account_reply(frame, "sparse", True)

    def test_empty_account_display_name_is_omitted_from_retrieval(self) -> None:
        frame = reply(self.report("mutation-sparse"), 12)
        frame["fields"].append({"id": 102, "hex": ""})
        with self.assertRaisesRegex(ValueError, "retrieval"):
            account_reply(frame, "sparse", True)

    def test_111_is_not_returned_even_when_stored(self) -> None:
        frame = reply(self.report("mutation-attribute65"), 12)
        frame["fields"].append({"id": 111, "hex": (b"X" * 64).hex()})
        with self.assertRaisesRegex(ValueError, "retrieval"):
            account_reply(frame, "attribute65", True)

    def test_empty_password_omits_presence_placeholder(self) -> None:
        frame = reply(self.report("mutation-absent"), 12)
        frame["fields"].append({"id": 106, "hex": "78"})
        with self.assertRaisesRegex(ValueError, "placeholder"):
            account_reply(frame, "absent", True)

    def test_retrieval_never_returns_the_actual_encoded_password(self) -> None:
        frame = reply(self.report("mutation-preserve"), 12)
        next(f for f in frame["fields"] if f["id"] == 106)["hex"] = bytes(
            x ^ 255 for x in b"account-base-26"
        ).hex()
        with self.assertRaisesRegex(ValueError, "placeholder"):
            account_reply(frame, "preserve", True)

    def test_literal_x_password_and_presence_placeholder_share_bytes(self) -> None:
        frame = reply(self.report("mutation-literal-x"), 12)
        self.assertEqual(fields(frame)[106], b"x")
        self.assertEqual(reply(self.report("login-literal-x"), 1)["error"], 0)
        self.assertEqual(reply(self.report("reject-literal-x"), 1)["error"], 1)

    def mutate_record(self, label: str, operation) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in [
                "native-seed",
                "native-final",
                "native-cleanup",
                "native-published",
            ]:
                shutil.copytree(BATCH / name, target / name)
            rows = json.loads((target / "native-final/extraction.json").read_text())[
                "records"
            ]
            row = next(
                r
                for r in rows
                if r["path"] == "/Hotline19/Users/m-au26-" + label + "/UserData"
            )
            path = target / "native-final" / (row["key"] + ".data")
            value = bytearray(path.read_bytes())
            operation(value)
            path.write_bytes(value)
            storage(target)

    def test_sentinel_does_not_preserve_all_32_bytes(self) -> None:
        def retain32(value: bytearray) -> None:
            value[700:702] = (32).to_bytes(2, "big")
            value[733] = ord("q") ^ 255

        with self.assertRaisesRegex(ValueError, "734-byte account record"):
            self.mutate_record("preserve32", retain32)

    def test_network_replacement_is_not_clipped_to_local_setters_31_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "734-byte account record"):
            self.mutate_record(
                "replace32",
                lambda v: v.__setitem__(slice(700, 702), (31).to_bytes(2, "big")),
            )

    def test_attribute65_is_stored_with_length64(self) -> None:
        with self.assertRaisesRegex(ValueError, "734-byte account record"):
            self.mutate_record(
                "attribute65",
                lambda v: v.__setitem__(slice(596, 598), (65).to_bytes(2, "big")),
            )

    def test_omitted_password_cannot_preserve_old_stored_value(self) -> None:
        with self.assertRaisesRegex(ValueError, "734-byte account record"):
            self.mutate_record(
                "absent",
                lambda v: v.__setitem__(slice(700, 702), (15).to_bytes(2, "big")),
            )

    def test_literal_x_is_not_the_nul_preservation_sentinel(self) -> None:
        with self.assertRaisesRegex(ValueError, "734-byte account record"):
            self.mutate_record("literal-x", lambda v: v.__setitem__(702, 0))

    def test_cleared_record_does_not_retain_opaque_attribute_bytes(self) -> None:
        with self.assertRaisesRegex(ValueError, "734-byte account record"):
            self.mutate_record("sparse", lambda v: v.__setitem__(598, ord("o")))


if __name__ == "__main__":
    unittest.main()
