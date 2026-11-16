"""Rejection and negative-control checks for the temporary-ban controls."""

import datetime as dt
import json
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import native_ban_expiry_cases as cases
import native_ban_expiry_control as control
import pytest
from ban_expiry_support import FakeRecorder, environment, iteration
from ban_expiry_wire import frame, identity_frames, probe_frames, roster_record


class BanExpiryPlanChecks:
    """Rejection and negative-control checks shared with BanExpiryTests."""

    def test_plan_source_and_runtime_rejections(self) -> None:
        """Changed plan sources and out-of-scope plans are rejected."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "plans"
            hashes = cases.write_plans(target, environment())
            assert set(hashes) == set(cases.plans()), "written plan names differ"
            for name in hashes:
                plan, actual = control.plan_gate(target / f"{name}.json")
                assert actual == name, "plan name differs"
                assert plan["endpoints"]["control"]["port"] == 15800, "port differs"
            changed = json.loads((target / "tempban.json").read_text())
            changed["steps"][0]["timeout"] = 11
            (target / "tempban.json").write_text(json.dumps(changed))
            with pytest.raises(
                ValueError, match=r"source plan hash changed|Prepared plan changed"
            ):
                control.plan_gate(target / "tempban.json")
        for mutation, message in (
            (
                {"source_a7_sha256": "wrong"},
                "Frozen A7 source-plan identity differs",
            ),
            ({"fixture_profile": "full"}, "Only control-only profile is prepared"),
            (
                {"full_file_baseline": "exercised"},
                "Only control-only profile is prepared",
            ),
        ):
            with iteration(mutation), pytest.raises(ValueError, match=message):
                cases.plan(
                    "tempban", cases.plans()["tempban"], environment() | mutation, 15800
                )
        with pytest.raises(ValueError, match="owned port"):
            cases.plan("tempban", cases.plans()["tempban"], environment(), 15500)

    def test_identity_and_notice_negative_controls(self) -> None:
        """Identity, roster, access and notice faults are each rejected."""
        good = identity_frames()
        control.identity_before_110(good, b"\0\x32", protected=False)
        control.identity_before_110(
            identity_frames(protected=True), b"\0\x32", protected=True
        )
        with pytest.raises(ValueError, match="UID/name"):
            control.identity_before_110(good, b"\0\x33", protected=False)
        extra = identity_frames()
        extra[-1] = frame(
            0,
            32,
            [
                (300, roster_record(1, b"framing-fixture")),
                (300, roster_record(50, cases.ZERO_NAME)),
                (300, roster_record(51, b"other")),
            ],
            "main",
            is_reply=1,
        )
        with pytest.raises(ValueError, match="roster target identity"):
            control.identity_before_110(extra, b"\0\x32", protected=False)
        with pytest.raises(ValueError, match="access"):
            control.identity_before_110(good, b"\0\x32", protected=True)
        bad = identity_frames()
        bad[1] = frame(354, 2, [(110, cases.ZERO_ACCESS)], "main")
        with pytest.raises(ValueError, match="privilege22"):
            control.identity_before_110(bad, b"\0\x32", protected=False)
        report = {
            "status": "completed",
            "completed_actions": len(cases.plans()["kick0"]),
            "frames": [
                *good,
                frame(104, 4, [(101, cases.TEMPORARY_NOTICE)], "target"),
                frame(0, 33, [], "main", is_reply=1),
                frame(302, 5, [(103, b"\0\x32")], "main"),
            ],
            "variables": {"target_uid": "0032"},
            "events": [{"connection": "target", "event": "eof"}],
        }
        with pytest.raises(ValueError, match="notice cardinality"):
            control.outcome_gate(report, "kick0")

    def test_timing_bounds_and_runtime_identity(self) -> None:
        """Timing windows bind the emulator identity and reject drift."""
        start = dt.datetime(2026, 11, 14, tzinfo=dt.UTC)
        value = {
            "request_utc": start.isoformat(),
            "ack_utc": (start + dt.timedelta(seconds=2)).isoformat(),
            "image_inode": 222,
            "emulator_pid": 9001,
            "emulator_start_ticks": 111,
            "emulator_sha256": "a" * 64,
            "namespace_inode": 456,
        }
        bound = control.TimingBounds.from_json(value)
        receipt = environment()
        assert bound.gate("pre", start + dt.timedelta(seconds=1690), receipt)[
            "host_window"
        ] == [1600, 1700], "pre window differs"
        assert bound.gate("post", start + dt.timedelta(seconds=1903), receipt)[
            "host_window"
        ] == [1900, 2400], "post window differs"
        for phase, elapsed in (("pre", 1690), ("post", 1903)):
            with iteration(phase):
                recorded = receipt | {"emulator_starttime": "111"}
                assert bound.gate(
                    phase, start + dt.timedelta(seconds=elapsed), recorded
                ) == bound.gate(
                    phase, start + dt.timedelta(seconds=elapsed), receipt
                ), "recorded identity differs"
                with pytest.raises(ValueError, match="identity changed"):
                    bound.gate(
                        phase,
                        start + dt.timedelta(seconds=elapsed),
                        receipt | {"emulator_starttime": "112"},
                    )
        assert not bound.gate("pre", start + dt.timedelta(seconds=1690), receipt)[
            "native_getdatetime_seconds_proven"
        ], "native time proven"
        with pytest.raises(ValueError, match="window"):
            bound.gate("pre", start + dt.timedelta(seconds=1701), receipt)
        with pytest.raises(ValueError, match="window"):
            bound.gate("post", start + dt.timedelta(seconds=1800), receipt)
        with pytest.raises(ValueError, match="identity changed"):
            bound.gate(
                "pre",
                start + dt.timedelta(seconds=1690),
                receipt | {"owned_working_image_inode": 223},
            )
        with pytest.raises(ValueError, match="bracket"):
            control.TimingBounds.from_json(
                value | {"ack_utc": (start + dt.timedelta(seconds=21)).isoformat()}
            )

    def test_fake_consumer_preserves_semantic_failure(self) -> None:
        """A fake recorder preserves a semantic failure of the probe."""
        post = cases.plan(
            "post-probe", cases.plans()["post-probe"], environment(), 15800
        )
        with (
            tempfile.TemporaryDirectory() as tmp,
            mock.patch.object(control, "Recorder", FakeRecorder),
        ):
            FakeRecorder.selected_frames = probe_frames(success=True)
            good = control.run_case(
                post,
                "post-probe",
                Path(tmp) / "good",
                dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2),
            )
            assert good["status"] == "completed", "good probe did not complete"
            FakeRecorder.selected_frames = (
                probe_frames(success=False) + probe_frames(success=True)[1:]
            )
            bad = control.run_case(
                post,
                "post-probe",
                Path(tmp) / "bad",
                dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2),
            )
            assert bad["status"] == "failed", "bad probe did not fail"
            assert "did not succeed" in bad["error"], "failure reason differs"
            assert (
                json.loads((Path(tmp) / "bad/report.json").read_text())["status"]
                == "failed"
            ), "report status differs"
            assert len(bad["events"]) == len(post["steps"]), "event count differs"

    def test_wrong_runner_namespace_stops_before_capture_or_socket_work(self) -> None:
        """A runner in the wrong namespace stops before any capture or socket work."""
        original = environment()
        deadline = dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2)
        with (
            mock.patch.object(control.os, "geteuid", return_value=0),
            mock.patch.object(control.os, "stat") as stat,
            mock.patch.object(
                control, "capture_gate", side_effect=AssertionError("capture")
            ) as capture,
        ):
            stat.return_value = SimpleNamespace(
                st_ino=original["emulator_netns_inode"] + 1
            )
            with pytest.raises(ValueError, match=r"Runner.*namespace"):
                control.runtime_gate(original, original, deadline)
            capture.assert_not_called()
            stat.assert_called_with("/proc/self/ns/net")
            stat.return_value = SimpleNamespace(st_ino=original["emulator_netns_inode"])
            with pytest.raises(AssertionError, match="capture"):
                control.runtime_gate(original, original, deadline)
            capture.assert_called_once_with(original)

    def test_live_runtime_binding_and_namespace_routes(self) -> None:
        """Live runtime bindings and namespace routes are checked in order."""
        original = environment()
        with (
            mock.patch.object(control.os, "geteuid", return_value=0),
            mock.patch.object(
                control, "capture_gate", side_effect=AssertionError("live")
            ),
        ):
            for key in (
                "emulator_starttime",
                "emulator_sha256",
                "emulator_netns_inode",
                "owned_working_image_inode",
            ):
                with iteration(key), pytest.raises(ValueError, match="plan"):
                    control.runtime_gate(
                        original | {key: "changed"},
                        original,
                        dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2),
                    )
        receipt = {
            "namespace_recorder_pid": 123,
            "emulator_pid": 456,
            "emulator_netns_inode": 789,
        }

        def inode(value: int) -> SimpleNamespace:
            """Build a fake stat result with one inode number.

            Returns
            -------
            types.SimpleNamespace
                The fake stat result.
            """
            return SimpleNamespace(st_ino=value)

        with (
            mock.patch.object(control.os, "stat", side_effect=[inode(789), inode(789)]),
            mock.patch.object(
                control.subprocess,
                "run",
                side_effect=[
                    SimpleNamespace(stdout="[]"),
                    SimpleNamespace(stdout="[]"),
                    SimpleNamespace(stdout='[{"ifname":"lo"}]'),
                ],
            ) as run,
        ):
            control.namespace_gate(receipt)
            assert run.call_count == 3, "route query count differs"
        with (
            mock.patch.object(control.os, "stat", side_effect=[inode(999), inode(789)]),
            pytest.raises(ValueError, match="not in the emulator namespace"),
        ):
            control.namespace_gate(receipt)
        with (
            mock.patch.object(control.os, "stat", side_effect=[inode(789), inode(789)]),
            mock.patch.object(
                control.subprocess,
                "run",
                side_effect=[SimpleNamespace(stdout='[{"dst":"default"}]')],
            ),
            pytest.raises(ValueError, match="routes changed"),
        ):
            control.namespace_gate(receipt)
