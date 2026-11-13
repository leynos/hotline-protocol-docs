"""Reject atomic-batch, rename-rejection and password-sentinel assumptions."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

import native_account_batch_cases as cases
import native_account_batch_model as model
from protocol_capture import decode_frame
from verify_native_account_batches import batch_result, catalogue, verify
from verify_native_auth import reply
from verify_native_shx import fields

BATCH = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-account-batch-01"
)


class AccountBatchTests(unittest.TestCase):
    def report(self, name: str) -> dict:
        return json.loads((BATCH / name / "report.json").read_text())

    def spec(self, name: str) -> dict:
        return next(s for s in cases.specifications() if s["case"] == name)

    def states(self, through: str) -> dict[str, model.State]:
        states = model.seed_states()
        for name, changes in model.effects().items():
            model.apply(states, changes)
            if name == through:
                return states
        raise ValueError(through)

    def snapshots(self) -> dict[str, dict[str, model.State]]:
        states = self.states("rename-collision")
        result = {
            "native-seed": model.seed_states(),
            "native-final": copy.deepcopy(states),
        }
        model.distinct_seed(states)
        result["native-distinct-seed"] = copy.deepcopy(states)
        model.distinct_effects(states)
        result["native-distinct-final"] = states
        return result

    def test_complete_paired_batch_and_stored_record_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual(
            (result["paired_connections"], result["terminal_batch_errors"]), (75, 11)
        )

    def test_outer_ids_zero_unknown_and_repeated_are_processed_in_order(self) -> None:
        plan = json.loads((BATCH / "batch-ordered-outer-ids/plan.json").read_text())
        request = next(
            decode_frame(bytes.fromhex(s["hex"]))
            for s in plan["steps"]
            if s["op"] == "send"
            and len(s["hex"]) >= 40
            and int(s["hex"][4:8], 16) == 349
        )
        self.assertEqual([f["id"] for f in request["fields"]], [0, 65000, 0])
        self.assertEqual(
            fields(reply(self.report("after-ordered-outer-ids"), 101))[102],
            b"Ordered done",
        )
        self.assertEqual(reply(self.report("after-ordered-outer-ids"), 100)["error"], 1)

    def test_collision_notice_is_not_a_terminal_error(self) -> None:
        report = self.report("batch-collision-continues")
        reply(report, 10)["error"] = 1
        with self.assertRaisesRegex(ValueError, "terminal ACK/error"):
            batch_result(report, self.spec("collision-continues"))

    def test_collision_notice_retains_its_109_marker(self) -> None:
        report = self.report("batch-collision-continues")
        notice = next(f for f in report["frames"] if f["type"] == 104)
        notice["fields"] = [f for f in notice["fields"] if f["id"] != 109]
        with self.assertRaisesRegex(ValueError, "collision notice"):
            batch_result(report, self.spec("collision-continues"))

    def test_malformed_record_does_not_roll_back_later_create(self) -> None:
        frame = reply(self.report("after-empty-copy-continues"), 100)
        frame["error"] = 1
        with self.assertRaisesRegex(ValueError, "Batch account state"):
            model.account_reply(
                frame, "after-empty-copy", self.states("empty-copy-continues")
            )

    def test_permission_failure_does_not_roll_back_earlier_create(self) -> None:
        frame = reply(self.report("after-create-update-denied"), 100)
        frame["error"] = 1
        with self.assertRaisesRegex(ValueError, "Batch account state"):
            model.account_reply(
                frame, "created-before-deny", self.states("create-update-denied")
            )

    def test_permission_failure_skips_later_items(self) -> None:
        frame = reply(self.report("after-create-update-denied"), 102)
        frame["error"] = 0
        with self.assertRaisesRegex(ValueError, "absent batch"):
            model.account_reply(
                frame, "skipped-create", self.states("create-update-denied")
            )

    def test_rename_collision_does_not_preserve_destination_display_record(
        self,
    ) -> None:
        frame = reply(self.report("after-rename-collision"), 102)
        next(f for f in frame["fields"] if f["id"] == 102)["hex"] = (
            b"Seed28-clash-new".hex()
        )
        with self.assertRaisesRegex(ValueError, "Batch account state"):
            model.account_reply(frame, "clash-new", self.states("rename-collision"))

    def test_rename_collision_does_not_skip_following_create(self) -> None:
        frame = reply(self.report("after-rename-collision"), 103)
        frame["error"] = 1
        with self.assertRaisesRegex(ValueError, "Batch account state"):
            model.account_reply(frame, "clash-skipped", self.states("rename-collision"))

    def test_native_permission_family_is_not_generic_list_saving_error(self) -> None:
        report = self.report("batch-delete-create-denied")
        reply(report, 10)["fields"][0]["hex"] = b"Error saving list of accounts.".hex()
        with self.assertRaisesRegex(ValueError, "terminal ACK/error"):
            batch_result(report, self.spec("delete-create-denied"))

    def test_per_item_subset_exemption_is_not_actor_full_access(self) -> None:
        report = self.report("batch-subset-exempt27")
        next(f for f in report["frames"] if f["type"] == 354)["fields"][0]["hex"] = (
            "fff3cfefff800000"
        )
        with self.assertRaisesRegex(ValueError, "role admission"):
            batch_result(report, self.spec("subset-exempt27"))

    def test_nul_create_password_is_literal_without_an_old_name(self) -> None:
        report = self.report("nul-password-login")
        self.assertEqual(reply(report, 1)["error"], 0)
        rows = json.loads((BATCH / "native-final/extraction.json").read_text())[
            "records"
        ]
        row = next(r for r in rows if r["path"].endswith("/m-b28-nul-new/UserData"))
        data = (BATCH / "native-final" / (row["key"] + ".data")).read_bytes()
        self.assertEqual(data[700:703], b"\0\1\0")

    def test_512_and_513_entries_have_distinct_captured_lengths(self) -> None:
        for length in [512, 513]:
            report = self.report(f"after-nested{length}")
            self.assertEqual(reply(report, 100)["error"], 0)
            plan = json.loads((BATCH / f"batch-nested{length}/plan.json").read_text())
            frame = next(
                decode_frame(bytes.fromhex(s["hex"]))
                for s in plan["steps"]
                if s["op"] == "send"
                and len(s["hex"]) >= 40
                and int(s["hex"][4:8], 16) == 349
            )
            self.assertEqual(len(bytes.fromhex(frame["fields"][0]["hex"])), length)

    def test_identity_beyond_copied_prefix_is_not_created(self) -> None:
        report = self.report("after-identity-after-limit")
        self.assertEqual(
            (reply(report, 100)["error"], reply(report, 101)["error"]), (1, 0)
        )

    def test_cleanup_refuses_unobserved_or_duplicate_identity(self) -> None:
        for labels in [["admin"], ["actor-create", "actor-create"]]:
            with self.subTest(labels=labels), self.assertRaises(ValueError):
                cases.cleanup(labels)

    def mutate_record(self, label: str, operation) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            target = Path(temporary)
            for name in [
                "native-seed",
                "native-final",
                "native-distinct-seed",
                "native-distinct-final",
                "native-cleanup",
                "native-published",
            ]:
                shutil.copytree(BATCH / name, target / name)
            rows = json.loads(
                (target / "native-distinct-final/extraction.json").read_text()
            )["records"]
            row = next(
                r
                for r in rows
                if r["path"] == "/Hotline19/Users/m-b28-" + label + "/UserData"
            )
            path = target / "native-distinct-final" / (row["key"] + ".data")
            data = bytearray(path.read_bytes())
            operation(data)
            path.write_bytes(data)
            catalogue(target, self.snapshots())

    def test_collision_destination_must_have_source_password(self) -> None:
        with self.assertRaisesRegex(ValueError, "stored account record"):
            self.mutate_record(
                "clash2-new", lambda data: data.__setitem__(702, ord("t") ^ 255)
            )

    def test_permission_bit27_is_retained_in_created_record(self) -> None:
        with self.assertRaisesRegex(ValueError, "stored account record"):
            self.mutate_record("grant-exempt", lambda data: data.__setitem__(7, 0))

    def test_batch_sparse_defaults_do_not_keep_old_attribute(self) -> None:
        with self.assertRaisesRegex(ValueError, "stored account record"):
            self.mutate_record("defaults", lambda data: data.__setitem__(598, ord("s")))


if __name__ == "__main__":
    unittest.main()
