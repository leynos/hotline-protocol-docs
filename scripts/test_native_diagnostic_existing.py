"""Offline bounds for the approved existing-fixture diagnostic load plans."""

import copy
import json
import unittest
from pathlib import Path

from native_diagnostic_existing_cases import CASES, NAME, build
from native_plan import packet, payload
from protocol_capture import decode_frame, validate_plan
from verify_native_diagnostic_existing import (
    check_cancellations,
    check_diagnostic,
    check_references,
    section_witness,
)


def control_sends(plan: dict) -> list[tuple[int, int, int]]:
    result = []
    for index, step in enumerate(plan["steps"]):
        if step["op"] != "send" or step["connection"] != "a":
            continue
        raw = bytes.fromhex(step["hex"][:16])
        if len(raw) < 8 or raw.startswith(b"TRTP"):
            continue
        result.append(
            (index, int.from_bytes(raw[2:4], "big"), int.from_bytes(raw[4:8], "big"))
        )
    return result


class PlanBoundsTests(unittest.TestCase):
    def setUp(self) -> None:
        self.plans = {name: build(name, {"emulator_pid": 1099659}) for name in CASES}

    def test_all_plans_validate_and_target_only_existing_file(self) -> None:
        for plan in self.plans.values():
            validate_plan(plan)
            kinds = {kind for _, kind, _ in control_sends(plan)}
            self.assertFalse(kinds & {203, 204, 304, 350, 351, 352})
            self.assertFalse(any(s["op"] == "shutdown_write" for s in plan["steps"]))
            self.assertEqual(plan["expectation"]["fixture_name_hex"], NAME.hex())

    def test_two_one_has_two_refs_one_data_socket_and_cleanup(self) -> None:
        plan = self.plans["one-active-one-queued"]
        sends = control_sends(plan)
        self.assertEqual([ident for _, kind, ident in sends if kind == 202], [11, 12])
        self.assertEqual([ident for _, kind, ident in sends if kind == 214], [15, 16])
        self.assertEqual(
            [ident for _, kind, ident in sends if kind == 303], [13, 14, 17]
        )
        self.assertEqual(
            [s["connection"] for s in plan["steps"] if s["op"] == "connect"],
            ["a", "active"],
        )
        self.assertEqual(
            (
                plan["expectation"]["global_download_limit"],
                plan["expectation"]["per_client_download_limit"],
            ),
            (2, 1),
        )

    def test_density_has_fixed_points_sixteen_refs_eight_sockets(self) -> None:
        plan = self.plans["density"]
        sends = control_sends(plan)
        self.assertEqual(
            [ident for _, kind, ident in sends if kind == 202],
            list(range(20, 28)) + list(range(40, 48)),
        )
        self.assertEqual(
            [ident for _, kind, ident in sends if kind == 214],
            list(range(77, 69, -1)) + list(range(87, 79, -1)),
        )
        self.assertEqual(
            [ident for _, kind, ident in sends if kind == 303], [35, 60, 61, 90]
        )
        self.assertEqual(
            len(
                [
                    s
                    for s in plan["steps"]
                    if s["op"] == "connect" and s["endpoint"] == "data"
                ]
            ),
            8,
        )
        self.assertFalse(any(s["op"] == "read_eof" for s in plan["steps"]))
        at = {ident: index for index, kind, ident in sends if kind == 303}
        for ident, active, queued in [(35, 4, 0), (60, 8, 4), (61, 8, 8)]:
            requests = [
                number
                for index, kind, number in sends
                if kind == 202 and index < at[ident]
            ]
            self.assertEqual(len(requests), active + queued)
        self.assertEqual(
            (
                plan["expectation"]["global_download_limit"],
                plan["expectation"]["per_client_download_limit"],
            ),
            (8, 8),
        )

    def test_postflight_is_read_only_and_restored_limits(self) -> None:
        plan = self.plans["postflight"]
        kinds = [kind for _, kind, _ in control_sends(plan)]
        self.assertEqual(kinds, [107, 348, 200, 206, 300, 303])
        self.assertEqual(
            (
                plan["expectation"]["global_download_limit"],
                plan["expectation"]["per_client_download_limit"],
                plan["expectation"]["per_ip_limit"],
            ),
            (100, 10, 5),
        )


class ReferenceWitnessTests(unittest.TestCase):
    def make_report(
        self, *, second_wait: bytes | None = b"\0\1", second_ref: bytes = b"\0\0\0\2"
    ) -> dict:
        first = [
            (108, (1_049_073).to_bytes(4, "big")),
            (207, (1_048_893).to_bytes(4, "big")),
            (107, b"\0\0\0\1"),
        ]
        second = [
            (108, (1_049_073).to_bytes(4, "big")),
            (207, (1_048_893).to_bytes(4, "big")),
            (107, second_ref),
        ]
        if second_wait is not None:
            second.append((116, second_wait))
        return {
            "frames": [
                decode_frame(bytes.fromhex(packet(0, 11, payload(first), reply=1))),
                decode_frame(bytes.fromhex(packet(0, 12, payload(second), reply=1))),
            ]
        }

    def test_positive_queue_requires_distinct_refs_and_nonzero_wait(self) -> None:
        result = check_references(self.make_report(), [11], [12])
        self.assertEqual(result["waiting_positions"], [1])
        with self.assertRaisesRegex(ValueError, "queue position"):
            check_references(self.make_report(second_wait=None), [11], [12])
        with self.assertRaisesRegex(ValueError, "queue position"):
            check_references(self.make_report(second_wait=b"\0\0"), [11], [12])
        with self.assertRaisesRegex(ValueError, "Duplicate transfer reference"):
            check_references(self.make_report(second_ref=b"\0\0\0\1"), [11], [12])


class CurrentUidTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/report.json"
        )
        cls.report = json.loads(path.read_text())

    def test_saved_current_uid_targets_one_row(self) -> None:
        result = check_diagnostic(self.report, 14, b"\0\6")
        self.assertEqual(result["field101_bytes"], 303)

    def test_stale_uid_cannot_be_relabelled_current(self) -> None:
        report = copy.deepcopy(self.report)
        event = next(
            e for e in report["events"] if e["event"] == "send" and e["action"] == 15
        )
        event["hex"] = event["hex"][:-4] + "ffff"
        with self.assertRaisesRegex(ValueError, "target differs"):
            check_diagnostic(report, 14, b"\0\6")


class SectionWitnessTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        path = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01/capture/report.json"
        )
        cls.report = json.loads(path.read_text())
        frame = next(f for f in cls.report["frames"] if f["is_reply"] and f["id"] == 14)
        cls.idle = bytes.fromhex(
            next(f["hex"] for f in frame["fields"] if f["id"] == 101)
        )
        loaded_path = (
            Path(__file__).resolve().parents[2]
            / "mothra/evidence/gap-remediation/2026-11-13/native-diagnostic-existing-01/one-active-one-queued/report.json"
        )
        loaded_report = json.loads(loaded_path.read_text())
        active_reply = next(
            f for f in loaded_report["frames"] if f["is_reply"] and f["id"] == 13
        )
        cls.captured = bytes.fromhex(
            next(f["hex"] for f in active_reply["fields"] if f["id"] == 101)
        )

    def loaded(self, active: int, waiting: int) -> bytes:
        text = self.idle
        for heading, count, row in [
            (b"-------- File Downloads ---------", active, NAME + b"  0% 1MB\r"),
            (b"------- Waiting Downloads -------", waiting, NAME + b"   (File)\r"),
        ]:
            if count:
                marker = b"\r\r" + heading + b"\r\r"
                text = text.replace(marker + b"None.", marker + row * count)
        return text

    def test_exact_captured_350_byte_native_witness(self) -> None:
        self.assertEqual(len(self.captured), 350)
        result = section_witness(self.captured, 1, 1)
        self.assertEqual(result["status"], "complete")
        self.assertEqual(result["observed_counts"], {"active": 1, "waiting": 1})

    def test_exact_counts_and_empty_unrelated_sections(self) -> None:
        for active, waiting in [(1, 1), (4, 0), (8, 4), (8, 8), (0, 0)]:
            self.assertEqual(
                section_witness(self.loaded(active, waiting), active, waiting)[
                    "status"
                ],
                "complete",
            )

    def test_queue_without_active_and_reduced_density_are_incomplete(self) -> None:
        self.assertEqual(
            section_witness(self.loaded(0, 1), 1, 1)["status"], "incomplete"
        )
        self.assertEqual(
            section_witness(self.loaded(7, 8), 8, 8)["status"], "incomplete"
        )

    def test_stale_post_cancel_row_and_truncation_are_incomplete(self) -> None:
        self.assertEqual(
            section_witness(self.loaded(1, 0), 0, 0)["status"], "incomplete"
        )
        self.assertEqual(
            section_witness(self.loaded(8, 8)[:600], 8, 8)["status"], "incomplete"
        )
        self.assertEqual(
            section_witness(self.loaded(8, 8)[:-2], 8, 8)["status"], "incomplete"
        )

    def test_swapped_grammars_and_clipped_file_token_are_incomplete(self) -> None:
        active = NAME + b"   5%   1M\r"
        waiting = NAME + b"   (File)\r"
        swapped = self.captured.replace(active, b"TEMPORARY\r")
        swapped = swapped.replace(waiting, active).replace(b"TEMPORARY\r", waiting)
        self.assertEqual(section_witness(swapped, 1, 1)["status"], "incomplete")
        clipped = self.captured.replace(b"(File)\r", b"(File\r")
        self.assertEqual(section_witness(clipped, 1, 1)["status"], "incomplete")

    def test_unrelated_upload_section_is_not_idle(self) -> None:
        marker = b"\r\r--------- File Uploads ----------\r\r"
        text = self.idle.replace(marker + b"None.", marker + NAME + b"  0% 1MB\r")
        self.assertEqual(section_witness(text, 0, 0)["status"], "incomplete")

    def test_cancellation_target_matches_saved_a7_ref(self) -> None:
        check_cancellations(self.report, {16: bytes.fromhex("00025b1b")})
        with self.assertRaisesRegex(ValueError, "another reference"):
            check_cancellations(self.report, {16: bytes.fromhex("00025b1c")})


if __name__ == "__main__":
    unittest.main()
