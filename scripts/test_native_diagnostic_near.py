"""Offline guards for the unexecuted A11 near-boundary packet."""

import importlib.util
import json
import unittest
from pathlib import Path

from native_diagnostic_existing_cases import NAME
from native_diagnostic_near_cases import build
from native_plan import packet, payload
from protocol_capture import decode_frame, validate_plan
from test_native_diagnostic_existing import control_sends
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_references,
    section_witness,
)
from verify_native_diagnostic_near import (
    expected_ids,
    near_complete,
    require_positions,
    sent_ids,
)


class NearPlanTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plan = build({"emulator_pid": 1099659})

    def test_exact_unique_ids_bounds_and_read_only_fixture(self) -> None:
        validate_plan(self.plan)
        sends = control_sends(self.plan)
        self.assertEqual([identifier for _, _, identifier in sends], expected_ids())
        self.assertEqual(len(expected_ids()), len(set(expected_ids())))
        self.assertEqual([kind for _, kind, _ in sends].count(202), 24)
        self.assertEqual([kind for _, kind, _ in sends].count(214), 24)
        self.assertEqual(
            [s["connection"] for s in self.plan["steps"] if s["op"] == "connect"],
            ["a"] + [f"active{i}" for i in range(8)],
        )
        self.assertFalse({203, 204, 304, 350, 351, 352} & {k for _, k, _ in sends})
        self.assertEqual(self.plan["expectation"]["maximum_references"], 24)
        self.assertEqual(self.plan["expectation"]["maximum_data_sockets"], 8)
        self.assertEqual(self.plan["expectation"]["fixture_name_hex"], NAME.hex())

    def test_fixed_points_and_saved_reference_placeholders(self) -> None:
        sends = control_sends(self.plan)
        self.assertEqual([i for _, k, i in sends if k == 303], [140, 141, 240])
        self.assertEqual(
            [i for _, k, i in sends if k == 202],
            list(range(100, 108)) + list(range(120, 136)),
        )
        by_id = {identifier: offset for offset, _, identifier in sends}
        self.assertEqual(
            sum(k == 202 and offset < by_id[140] for offset, k, _ in sends), 16
        )
        self.assertEqual(
            sum(k == 202 and offset < by_id[141] for offset, k, _ in sends), 24
        )
        self.assertEqual(
            [i for _, k, i in sends if k == 214],
            list(range(215, 199, -1)) + list(range(227, 219, -1)),
        )
        cancel_steps = [
            s
            for s in self.plan["steps"]
            if s["op"] == "send"
            and "{queued" in s["hex"]
            or s["op"] == "send"
            and "{active" in s["hex"]
            and s["connection"] == "a"
        ]
        self.assertEqual(len(cancel_steps), 24)
        self.assertEqual(
            [s["hex"].split("{")[1].split("}")[0] for s in cancel_steps],
            [f"queued{i}" for i in reversed(range(16))]
            + [f"active{i}" for i in reversed(range(8))],
        )


class NearWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-density-01/verification-density.json"
        )
        data = json.loads(path.read_text())["diagnostics"]
        cls.actual_8_8 = bytes.fromhex(data["61"]["field101_hex"])
        cls.idle = bytes.fromhex(data["90"]["field101_hex"])
        marker = b"\r\r------- Waiting Downloads -------\r\r"
        cls.synthetic_8_16 = cls.actual_8_8.replace(
            marker, marker + (NAME + b"   (File)\r") * 8, 1
        )

    def test_saved_eight_eight_and_predicted_sixteen_rows(self) -> None:
        self.assertEqual(len(self.actual_8_8), 763)
        self.assertEqual(len(self.synthetic_8_16), 995)
        witnesses = {
            "140": section_witness(self.actual_8_8, 8, 8),
            "141": section_witness(self.synthetic_8_16, 8, 16),
            "240": section_witness(self.idle, 0, 0),
        }
        self.assertTrue(
            near_complete(
                {"140": {"field101_bytes": 763}, "141": {"field101_bytes": 995}},
                witnesses,
            )
        )

    def test_wrong_rows_size_and_stale_idle_fail(self) -> None:
        wrong_rows = section_witness(self.actual_8_8, 8, 16)
        clipped = section_witness(self.synthetic_8_16[:-3], 8, 16)
        self.assertEqual(wrong_rows["status"], "incomplete")
        self.assertEqual(clipped["status"], "incomplete")
        complete = {
            "140": {"status": "complete"},
            "141": {"status": "complete"},
            "240": {"status": "complete"},
        }
        self.assertFalse(
            near_complete(
                {"140": {"field101_bytes": 763}, "141": {"field101_bytes": 994}},
                complete,
            )
        )
        complete["240"] = section_witness(self.actual_8_8, 0, 0)
        self.assertFalse(
            near_complete(
                {"140": {"field101_bytes": 763}, "141": {"field101_bytes": 995}},
                complete,
            )
        )

    def test_queue_positions_and_wrong_cancel_reference_fail(self) -> None:
        def frame(identifier: int, ref: int, queue: int | None) -> dict:
            fields = [
                (107, ref.to_bytes(4, "big")),
                (108, (1_049_073).to_bytes(4, "big")),
                (207, (1_048_893).to_bytes(4, "big")),
            ]
            if queue is not None:
                fields.append((116, queue.to_bytes(2, "big")))
            return decode_frame(
                bytes.fromhex(packet(0, identifier, payload(fields), reply=1))
            )

        report = {"frames": [frame(100, 1, None), frame(120, 2, 1)]}
        self.assertEqual(
            check_references(report, [100], [120])["waiting_positions"], [1]
        )
        require_positions(list(range(1, 17)))
        with self.assertRaisesRegex(ValueError, "Queue positions differ"):
            require_positions(list(range(1, 16)) + [15])
        report["frames"][1] = frame(120, 2, 0)
        with self.assertRaisesRegex(ValueError, "queue position"):
            check_references(report, [100], [120])
        report = {
            "frames": [frame(200, 1, None)],
            "events": [
                {
                    "event": "send",
                    "connection": "a",
                    "hex": packet(214, 200, payload([(107, b"BAD!")])),
                }
            ],
        }
        with self.assertRaisesRegex(ValueError, "targeted another reference"):
            check_cancellations(report, {200: b"GOOD"})

    def test_duplicate_request_ids_are_detectable(self) -> None:
        report = {
            "events": [
                {"event": "send", "connection": "a", "hex": packet(202, 100)},
                {"event": "send", "connection": "a", "hex": packet(202, 100)},
            ]
        }
        ids = sent_ids(report)
        self.assertEqual(ids, [100, 100])
        self.assertNotEqual(len(ids), len(set(ids)))

    def test_guest_only_ack_tail_rejects_wrong_id_status_and_clip(self) -> None:
        source = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-near-01/verify_partial.py"
        )
        spec = importlib.util.spec_from_file_location("a12_partial", source)
        assert spec is not None and spec.loader is not None
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        saved = bytes.fromhex("00010000000000cf0000000000000002000000020000")
        self.assertEqual(module.guest_ack_tail(saved)["frame"]["id"], 207)
        for malformed in (
            saved[:-1],
            saved[:7] + b"\xce" + saved[8:],
            saved[:11] + b"\x01" + saved[12:],
        ):
            with self.assertRaises(ValueError):
                module.guest_ack_tail(malformed)


if __name__ == "__main__":
    unittest.main()
