"""Offline contract tests for the bounded same-session 304 fixture."""

import copy
import unittest
from pathlib import Path

import native_settings_transition_cases as cases
from protocol_capture import validate_plan
from verify_native_settings_transition import check_stage, semantic

BASELINE = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/plan.json"
)


def frame(
    kind: int,
    action: int,
    connection: str,
    values: dict[int, bytes],
    *,
    reply: int = 0,
    identifier: int = 0,
) -> dict:
    return {
        "type": kind,
        "action": action,
        "connection": connection,
        "is_reply": reply,
        "id": identifier,
        "error": 0,
        "fields": [{"id": key, "hex": value.hex()} for key, value in values.items()],
    }


def sample(stage: cases.Stage, window: dict, uid: bytes = b"\0\x21") -> dict:
    name, icon = stage.expected_name, stage.expected_icon
    frames = [
        frame(301, window["first"] + 1, "main", {103: uid, 102: name, 104: icon}),
        frame(301, window["first"] + 2, "subject", {103: uid, 102: name, 104: icon}),
        frame(
            108, window["first"] + 4, "main", {}, reply=1, identifier=window["pm_id"]
        ),
        frame(
            104,
            window["first"] + 5,
            "subject",
            {
                103: b"\0\x20",
                102: b"framing-fixture",
                113: b"\0\1",
                101: bytes.fromhex(window["pm_text_hex"]),
            },
        ),
    ]
    if stage.expected_auto is not None:
        frames.append(
            frame(
                104,
                window["first"] + 6,
                "main",
                {103: uid, 102: name, 113: b"\0\4", 101: stage.expected_auto},
            )
        )
    return {"frames": frames}


class SettingsTransitionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.baseline_raw = BASELINE.read_bytes()
        cls.baseline = cases.load_baseline(cls.baseline_raw)
        cls.plan = cases.plans(cls.baseline["environment"], cls.baseline_raw)["observe"]

    def test_full_baseline_and_bounded_unique_sequence(self) -> None:
        pair = cases.plans(self.baseline["environment"], self.baseline_raw)
        self.assertEqual(pair["preflight"], pair["postflight"])
        self.assertEqual(pair["preflight"]["steps"], self.baseline["steps"])
        self.assertEqual(len(pair["preflight"]["steps"]), 29)
        validate_plan(self.plan)
        self.assertEqual(self.plan["expectation"]["pm_count"], 8)
        self.assertEqual(
            [w["label"] for w in self.plan["expectation"]["windows"]],
            [s.label for s in cases.STAGES],
        )
        steps = self.plan["steps"]
        self.assertEqual(
            sum(s["op"] == "send" and int(s["hex"][4:8], 16) == 108 for s in steps), 8
        )
        self.assertEqual(steps[-2]["op"], "close")
        self.assertEqual(steps[-1]["op"], "close")
        self.assertIn(
            "{peer_uid}", "".join(s["hex"] for s in steps if s["op"] == "send")
        )
        self.assertEqual(
            len({w["pm_text_hex"] for w in self.plan["expectation"]["windows"]}), 8
        )
        self.assertFalse(
            any(
                s["op"] == "send"
                and int(s["hex"][4:8], 16) in {121, 350, 351, 353, 203, 204}
                for s in steps
            )
        )

    def test_identity_and_baseline_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "SHA-256"):
            cases.load_baseline(self.baseline_raw + b" ")
        with self.assertRaisesRegex(ValueError, "Runtime identity"):
            cases.plans(
                dict(self.baseline["environment"], emulator_pid=-1), self.baseline_raw
            )

    def test_each_stage_accepts_exact_synthetic_witness(self) -> None:
        for stage, window in zip(
            cases.STAGES, self.plan["expectation"]["windows"], strict=True
        ):
            with self.subTest(stage=stage.label):
                result = check_stage(
                    sample(stage, window), self.plan, window, b"\0\x21"
                )
                self.assertEqual(result["label"], stage.label)

    def test_rejects_wrong_default_missing_feedback_and_wrong_301(self) -> None:
        window = self.plan["expectation"]["windows"][1]
        report = sample(cases.STAGES[1], window)
        wrong = copy.deepcopy(report)
        wrong["frames"][-1]["fields"][-1]["hex"] = b"stale-explicit".hex()
        with self.assertRaisesRegex(ValueError, "automatic text"):
            check_stage(wrong, self.plan, window, b"\0\x21")
        with self.assertRaisesRegex(ValueError, "104 delivery"):
            check_stage({"frames": report["frames"][:-1]}, self.plan, window, b"\0\x21")
        wrong = copy.deepcopy(report)
        wrong["frames"][0]["fields"][2]["hex"] = b"\0\7".hex()
        with self.assertRaisesRegex(ValueError, "301 name/icon"):
            check_stage(wrong, self.plan, window, b"\0\x21")

    def test_rejects_extra_feedback_and_stale_uid(self) -> None:
        window = self.plan["expectation"]["windows"][3]
        report = sample(cases.STAGES[3], window)
        wrong = copy.deepcopy(report)
        wrong["frames"].append(
            frame(104, window["first"] + 6, "main", {101: b"unexpected"})
        )
        with self.assertRaisesRegex(ValueError, "104 delivery"):
            check_stage(wrong, self.plan, window, b"\0\x21")
        with self.assertRaisesRegex(ValueError, "301 name/icon/UID"):
            check_stage(report, self.plan, window, b"\0\x22")

    def test_complete_semantic_rejects_failed_report(self) -> None:
        with self.assertRaisesRegex(ValueError, "did not complete"):
            semantic({"status": "failed", "frames": []}, self.plan)


if __name__ == "__main__":
    unittest.main()
