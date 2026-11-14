"""Offline faults at the owned-account cleanup boundary."""

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import native_ban_expiry_cleanup as cleanup
from native_auth_cases import complement
from native_control_readiness import ORIGINAL_ACCOUNTS


def frame(identifier: int, error: int, values: dict[int, bytes]) -> dict:
    return {
        "connection": "main",
        "is_reply": 1,
        "id": identifier,
        "error": error,
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()],
    }


def report(stage: str) -> dict:
    frames = []
    for identifier, key, name, access in (
        (
            20,
            cleanup.expiry.ZERO_KEY,
            cleanup.expiry.ZERO_NAME,
            cleanup.expiry.ZERO_ACCESS,
        ),
        (
            21,
            cleanup.expiry.PROTECTED_KEY,
            cleanup.expiry.PROTECTED_NAME,
            cleanup.expiry.PROTECTED_ACCESS,
        ),
    ):
        if stage == "guard":
            frames.append(
                frame(
                    identifier,
                    0,
                    {102: name, 105: complement(key), 106: b"x", 110: access},
                )
            )
        else:
            frames.extend(
                (
                    frame(identifier, 0, {}),
                    frame(
                        identifier + 2,
                        1,
                        {100: b"No account with login \xd2" + key + b"\xd3."},
                    ),
                )
            )
    if stage == "delete":
        frames.append(
            {
                "connection": "main",
                "is_reply": 1,
                "id": 24,
                "error": 0,
                "fields": [
                    {"id": 101, "hex": value}
                    for value in sorted(ORIGINAL_ACCOUNTS, reverse=True)
                ],
            }
        )
    return {
        "status": "completed",
        "completed_actions": len(cleanup.steps(stage)),
        "frames": frames,
    }


class CleanupTests(unittest.TestCase):
    def test_produced_plans_touch_only_owned_keys(self) -> None:
        for stage, opcode in (("guard", 352), ("delete", 351)):
            plan = cleanup.make_plan(
                stage,
                {
                    "fixture_profile": "control-only",
                    "full_file_baseline": "not_exercised",
                },
                "a" * 64,
                None,
            )
            self.assertEqual(plan["endpoints"]["control"]["port"], 15800)
            sends = [
                bytes.fromhex(s["hex"]) for s in plan["steps"] if s["op"] == "send"
            ]
            self.assertEqual(
                sum(int.from_bytes(raw[2:4], "big") == opcode for raw in sends), 2
            )
            self.assertFalse(any(b"fixture-low" in raw for raw in sends))

    def test_guard_rejects_wrong_name_key_access_and_status(self) -> None:
        cleanup.semantic(report("guard"), "guard")
        for field_id in (102, 105, 110):
            broken = report("guard")
            next(f for f in broken["frames"][0]["fields"] if f["id"] == field_id)[
                "hex"
            ] = "00"
            with self.subTest(field_id=field_id), self.assertRaises(ValueError):
                cleanup.semantic(broken, "guard")
        broken = report("guard")
        broken["status"] = "failed"
        with self.assertRaisesRegex(ValueError, "incomplete"):
            cleanup.semantic(broken, "guard")

    def test_delete_requires_missing_proof_and_original_enumeration(self) -> None:
        cleanup.semantic(report("delete"), "delete")
        for identifier in (22, 23):
            broken = report("delete")
            next(f for f in broken["frames"] if f["id"] == identifier)["error"] = 0
            with (
                self.subTest(identifier=identifier),
                self.assertRaisesRegex(ValueError, "readback"),
            ):
                cleanup.semantic(broken, "delete")
        broken = report("delete")
        broken["frames"][-1]["fields"].pop()
        with self.assertRaisesRegex(ValueError, "two-account"):
            cleanup.semantic(broken, "delete")

    def test_deletion_generation_fails_closed_without_accepted_guard(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            env = {
                "fixture_profile": "control-only",
                "full_file_baseline": "not_exercised",
            }
            runtime, guard = root / "runtime.json", root / "guard"
            runtime.write_text(json.dumps(env))
            guard.mkdir()
            (guard / "plan.json").write_text(
                json.dumps(cleanup.make_plan("guard", env, "a" * 64, None))
            )
            (guard / "report.json").write_text("{}")
            with (
                patch.object(cleanup, "accepted_post", return_value="a" * 64),
                patch.object(cleanup, "verify_capture", return_value=report("guard")),
            ):
                cleanup.prepare(
                    "delete", root / "post", runtime, root / "delete", guard
                )
            self.assertTrue((root / "delete/plan.json").is_file())
            broken = report("guard")
            broken["frames"][0]["fields"][0]["hex"] = "00"
            with (
                patch.object(cleanup, "accepted_post", return_value="a" * 64),
                patch.object(cleanup, "verify_capture", return_value=broken),
                self.assertRaisesRegex(ValueError, "readback"),
            ):
                cleanup.prepare(
                    "delete", root / "post", runtime, root / "blocked", guard
                )
            self.assertFalse((root / "blocked").exists())


if __name__ == "__main__":
    unittest.main()
