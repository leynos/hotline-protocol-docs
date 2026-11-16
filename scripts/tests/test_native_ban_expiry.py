"""Offline controls for the finite temporary-ban fixture and its runner."""

import datetime as dt
import hashlib
import json
import tempfile
import time
from pathlib import Path
from types import SimpleNamespace
from unittest import mock

import native_ban_expiry_cases as cases
import native_ban_expiry_control as control
import pytest
from ban_expiry_support import environment, iteration
from protocol_capture import validate_plan
from test_native_ban_expiry_plan import BanExpiryPlanChecks


def show_props(actual: dict) -> SimpleNamespace:
    """Render unit properties as the ``systemctl show`` output that they would be.

    Returns
    -------
    types.SimpleNamespace
        The fake process result whose ``stdout`` lists the properties.
    """
    return SimpleNamespace(stdout="".join(f"{k}={v}\n" for k, v in actual.items()))


class BanExpiryTests(BanExpiryPlanChecks):
    """Offline controls for the finite temporary-ban fixture and its runner."""

    def test_named_live_service_rechecks_actual_cap_and_coverage(self) -> None:
        """A named live service is rechecked for its actual cap and coverage."""
        deadline = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=1200)
        monotonic_us = time.monotonic_ns() // 1000
        props = {
            "ActiveState": "active",
            "SubState": "running",
            "MainPID": "321",
            "RuntimeMaxUSec": "35min",
            "ActiveEnterTimestampMonotonic": str(monotonic_us - 100_000_000),
            "KillMode": "control-group",
        }
        meta = {
            "unit": "mothra-alias-test.service",
            "pid": 321,
            "unit_properties": props,
        }
        with mock.patch.object(
            control.subprocess, "run", return_value=show_props(props)
        ) as run:
            control.live_service(meta, deadline, 2100)
            run.assert_called_once()
        for changed, expected in (
            ({"RuntimeMaxUSec": "2101s"}, "Managed service changed"),
            (
                {"ActiveEnterTimestampMonotonic": str(monotonic_us - 1_100_000_000)},
                "expires before epoch deadline",
            ),
        ):
            with iteration(changed):
                actual = props | changed
                recorded = (
                    meta
                    if "RuntimeMaxUSec" in changed
                    else meta | {"unit_properties": actual}
                )
                with (
                    mock.patch.object(
                        control.subprocess, "run", return_value=show_props(actual)
                    ),
                    pytest.raises(ValueError, match=expected),
                ):
                    control.live_service(recorded, deadline, 2100)
        over_cap = props | {"RuntimeMaxUSec": "2101s"}
        with (
            mock.patch.object(
                control.subprocess, "run", return_value=show_props(over_cap)
            ),
            pytest.raises(ValueError, match="Managed service changed"),
        ):
            control.live_service(meta | {"unit_properties": over_cap}, deadline, 2100)
        with (
            mock.patch.object(
                control.subprocess, "run", return_value=show_props(props)
            ),
            pytest.raises(ValueError, match="Managed service changed"),
        ):
            control.live_service(meta, deadline)  # Legacy caller requires 900 seconds.

    def test_named_runtime_gate_passes_2100_to_all_managed_units(self) -> None:
        """The runtime gate passes the 2100-second cap to every managed unit."""
        profile = "native-missing-alias-ui-30m-v1"
        deadline = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=1200)
        env = environment() | {
            "capture_window_profile": profile,
            "capture_window_purpose": "native-missing-alias-positive",
        }
        props = {
            "ActiveState": "active",
            "MainPID": "321",
            "RuntimeMaxUSec": "35min",
            "KillMode": "control-group",
        }

        def unit(pid: int) -> dict:
            """Describe one managed unit with its own main process identifier.

            Returns
            -------
            dict
                The unit record that the runtime gate reads.
            """
            return {
                "pid": pid,
                "fd": 4,
                "deadline_utc": deadline.isoformat(),
                "unit_properties": props | {"MainPID": str(pid)},
            }

        receipt = env | {
            "guest_pcap": "/guest.pcap",
            "epoch_started_utc": (deadline - dt.timedelta(seconds=1800)).isoformat(),
            "managed_capture": {"host": unit(321), "namespace": unit(322)},
            "host_recorder_pid": 321,
            "namespace_recorder_pid": 322,
            "host_pcap": "/host.pcap",
            "namespace_pcap": "/namespace.pcap",
            "managed_lock": unit(323) | {"busy_exit": 1},
            "oracle_lock": "/oracle.lock",
        }
        with pytest.raises(ValueError, match="profile"):
            control.runtime_gate(receipt, env, deadline)
        with (
            mock.patch.object(control.os, "geteuid", return_value=0),
            mock.patch.object(
                control.os, "stat", return_value=SimpleNamespace(st_ino=456)
            ),
            mock.patch.object(control.os, "readlink", return_value="/guest.pcap"),
            mock.patch.object(control, "capture_gate"),
            mock.patch.object(control, "namespace_gate"),
            mock.patch.object(
                control.Path, "stat", return_value=SimpleNamespace(st_ino=222, st_dev=1)
            ),
            mock.patch.object(
                control.Path, "read_text", return_value="flags:\t0100001\n"
            ),
            mock.patch.object(control, "live_service") as live,
            mock.patch.object(
                control.subprocess, "run", return_value=SimpleNamespace(returncode=1)
            ),
        ):
            control.runtime_gate(receipt, env, deadline, capture_window_profile=profile)
            assert live.call_count == 3, "managed unit count differs"
            assert [call.args[2] for call in live.call_args_list] == [2100] * 3, (
                "managed unit cap differs"
            )

    def test_window_profile_requires_alias_purpose_and_explicit_selection(
        self,
    ) -> None:
        """The capture window needs the alias purpose and an explicit selection."""
        profile = "native-missing-alias-ui-30m-v1"
        assert control.capture_window_bounds({}, {}, None) == (720, 900), "default"
        values = {
            "capture_window_profile": profile,
            "capture_window_purpose": "native-missing-alias-positive",
        }
        assert control.capture_window_bounds(values, values, profile) == (
            1800,
            2100,
        ), "alias window differs"
        for receipt, env, selected, message in (
            (values, values, None, "Capture window profile differs"),
            (values, values, "unknown", "Capture window profile differs"),
            (
                values,
                {**values, "capture_window_purpose": "other"},
                profile,
                "Capture window purpose differs",
            ),
            ({}, values, profile, "Capture window profile differs"),
        ):
            with iteration(selected), pytest.raises(ValueError, match=message):
                control.capture_window_bounds(receipt, env, selected)

    def test_production_plans_are_finite_and_byte_pinned(self) -> None:
        """The production plans are finite, validated and byte-pinned."""
        generated = cases.plans()
        assert set(generated) == {
            "readiness",
            *control.EPOCH_CASES["first"],
            "pre-probe",
            "post-probe",
        }, "plan names differ"
        assert len(generated["readiness"]) == 18, "readiness step count differs"
        assert len(generated["tempban"]) == 24, "tempban step count differs"
        assert generated["protected"][-3]["op"] == "expect_quiet", "quiet step differs"
        for name, steps in generated.items():
            with iteration(name):
                plan = cases.plan(name, steps, environment(), 15800)
                validate_plan(plan)
                assert plan["environment"]["full_file_baseline"] == "not_exercised", (
                    "baseline differs"
                )
                sends = [s["hex"] for s in steps if s["op"] == "send"]
                assert not any(
                    x.startswith("000000ca") or "48545846" in x for x in sends
                ), "forbidden send present"
        for name, option in (("kick0", "007100020000"), ("tempban", "007100020001")):
            with iteration(name):
                kick = [
                    s
                    for s in generated[name]
                    if s["op"] == "send" and s["hex"].startswith("0000006e")
                ]
                assert len(kick) == 1, "kick count differs"
                assert "00670002{target_uid}" in kick[0]["hex"], "target missing"
                assert option in kick[0]["hex"], "option differs"
                assert "006500" not in kick[0]["hex"], "forbidden option present"
        assert generated["immediate-probe"] == generated["pre-probe"], "pre-probe"
        assert generated["kick0-probe"] == generated["post-probe"], "post-probe"

    def test_later_epochs_never_require_admin_login_readiness(self) -> None:
        """Later epochs never require admin login readiness before their probe."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases.write_plans(root / "plans", environment())
            (root / "binary").write_bytes(b"oracle")
            now = dt.datetime.now(dt.UTC)
            (root / "receipt.json").write_text(
                json.dumps({
                    "deadline_utc": (now + dt.timedelta(minutes=2)).isoformat()
                })
            )
            (root / "clock.json").write_text(
                json.dumps(
                    control.TimingBounds(
                        now, now, 222, 9001, 111, "a" * 64, 456
                    ).to_json()
                )
            )
            for phase, marker in (
                ("pre", "not_exercised_ban_active"),
                ("post", "not_exercised_preserve_first_lookup"),
            ):
                with (
                    iteration(phase),
                    mock.patch.object(control, "runtime_gate"),
                    mock.patch.object(control.TimingBounds, "gate", return_value={}),
                    mock.patch.object(
                        control,
                        "verify_capture",
                        side_effect=AssertionError("prior107"),
                    ),
                    mock.patch.object(
                        control,
                        "run_case",
                        return_value={"status": "completed", "error": ""},
                    ) as run,
                    mock.patch.object(
                        control,
                        "ORACLE_SHA256",
                        hashlib.sha256(b"oracle").hexdigest(),
                    ),
                ):
                    result = control.run_epoch(
                        phase,
                        root / "plans",
                        None,
                        root / "receipt.json",
                        root / "binary",
                        root / phase,
                        bounds_path=root / "clock.json",
                    )
                    assert result["preprobe_baseline"] == marker, "baseline differs"
                    assert result["readiness_report_sha256"] is None, "readiness ran"
                    assert run.call_count == 1, "probe count differs"
                    assert run.call_args.args[1] == f"{phase}-probe", "probe differs"

    def test_first_epoch_settles_before_any_account_socket(self) -> None:
        """The first epoch settles before any account socket is opened."""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            cases.write_plans(root / "plans", environment())
            ready = root / "ready"
            ready.mkdir()
            (ready / "plan.json").write_bytes(
                (root / "plans/readiness.json").read_bytes()
            )
            (ready / "report.json").write_text("{}")
            (root / "binary").write_bytes(b"oracle")
            (root / "receipt.json").write_text(
                json.dumps({
                    "deadline_utc": (
                        dt.datetime.now(dt.UTC) + dt.timedelta(minutes=2)
                    ).isoformat()
                })
            )
            sequence = []
            clock = control.TimingBounds(
                dt.datetime.now(dt.UTC),
                dt.datetime.now(dt.UTC),
                222,
                9001,
                111,
                "a" * 64,
                456,
            )

            def fake_case(_plan: dict, name: str, *_args: object) -> dict:
                """Record one case name in the order that the cases run.

                Returns
                -------
                dict
                    A completed, error-free case result.
                """
                sequence.append(name)
                return {"status": "completed", "error": ""}

            with (
                mock.patch.multiple(
                    control,
                    runtime_gate=lambda *_: None,
                    verify_capture=lambda *_: {
                        "oracle_sha256": hashlib.sha256(b"oracle").hexdigest()
                    },
                    readiness=lambda *_: None,
                    run_case=fake_case,
                    ban_timing=lambda *_: clock,
                    ORACLE_SHA256=hashlib.sha256(b"oracle").hexdigest(),
                ),
                mock.patch.object(
                    control.time,
                    "sleep",
                    side_effect=lambda n: sequence.append(f"settle-{n}"),
                ),
                mock.patch.object(
                    control.time, "monotonic_ns", side_effect=[0, 35_000_000_000]
                ),
            ):
                result = control.run_epoch(
                    "first",
                    root / "plans",
                    ready,
                    root / "receipt.json",
                    root / "binary",
                    root / "out",
                )
            assert result["status"] == "completed", "epoch did not complete"
            assert sequence == ["settle-35", *control.EPOCH_CASES["first"]], (
                "case order differs"
            )
            assert result["post_readiness_settle"]["elapsed_seconds"] == 35, (
                "settle time differs"
            )
