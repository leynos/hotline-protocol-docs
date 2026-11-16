"""Offline controls for the one-alias positive rehearsal."""

import contextlib
import datetime as dt
import io
import json
import os
import re
import socket
import tempfile
import typing as typ
from pathlib import Path
from unittest import mock

import native_missing_alias_cases as cases
import native_missing_alias_control as control
import pytest
from missing_alias_support import (
    ENV,
    PRESTAGED_FINFO,
    FakeWire,
    reply,
    row,
    stage_owned_files,
)
from protocol_capture import decode_frame

UNSUPPORTED_WINDOW = "Unsupported alias capture window profile or purpose"
NOT_IDENTIFIED = "206 did not identify the resolved tagged alias"
GATE_DIFFERS = "Finder UI gate/one-alias action differs"


class AliasPlanTests:
    """Offline controls for the plan, the frames, the host state and the gate."""

    def test_one_owned_path_and_exact_budget(self) -> None:
        """Keep one owned path and the exact request budget of the plan."""
        plan = cases.source_plan(ENV)
        assert [r["kind"] for r in plan["requests"]] == [205, 200, 200, 206], (
            "request kinds"
        )
        assert [r["id"] for r in plan["requests"]] == [10, 11, 12, 13], "request ids"
        assert plan["case_numbered_with_login"] == 5, "numbered with login"
        assert plan["total_numbered_including_readiness"] == 11, "numbered total"
        assert plan["handshakes"] == 2, "handshakes"
        assert plan["barrier500_requests"] == 0, "no barrier-500 requests"
        assert plan["mutations"] == 1, "one mutation"
        assert "unlink" not in repr(plan).lower(), "no unlink in the plan"

    def test_named_alias_window_keeps_request_budget(self) -> None:
        """Keep the request budget under the named alias capture window."""
        env = {
            **ENV,
            "capture_window_profile": "native-missing-alias-ui-30m-v1",
            "capture_window_purpose": "native-missing-alias-positive",
        }
        plan = cases.source_plan(env)
        assert plan["limits"]["epoch_seconds"] == 1800, "named window length"
        assert plan["requests"] == cases.source_plan(ENV)["requests"], "same requests"
        for change in (
            {"capture_window_purpose": "other"},
            {"capture_window_profile": "unknown"},
        ):
            with pytest.raises(ValueError, match=re.escape(UNSUPPORTED_WINDOW)):
                cases.source_plan({**env, **change})

    def test_source_pin_and_dynamic_206(self) -> None:
        """Refuse a bad pin and build the dynamic 206 from the alias name."""
        for pin, message in (
            ("", "Incomplete runtime identity"),
            ("Z" * 64, "Invalid pre-staged Finder-info SHA-256"),
            ("a" * 63, "Invalid pre-staged Finder-info SHA-256"),
        ):
            with pytest.raises(ValueError, match=re.escape(message)):
                cases.source_plan({**ENV, "initial_finf_sha256": pin})
        with tempfile.TemporaryDirectory() as temp:
            folder = Path(temp) / "plan"
            cases.write_plan(folder, ENV)
            plan = control.prepared(folder)
            assert plan["total_numbered_including_readiness"] == 11, "numbered total"
            alias = b"copied alias"
            raw = cases.request_hex(plan["requests"][3], alias)
            decoded = decode_frame(bytes.fromhex(raw))
            assert decoded["type"] == 206, "resolve request type"
            name_field = {"id": 201, "hex": alias.hex()}
            path_field = {"id": 202, "hex": cases.ROOT_PATH.hex()}
            assert decoded["fields"] == [name_field, path_field], "alias and root"
            (folder / "source-hashes.json").write_text("{}", encoding="utf-8")
            with pytest.raises(ValueError, match="source hash"):
                control.prepared(folder)

    def test_tagged_alias_206_and_semantic_faults(self) -> None:
        """Accept the tagged 206 and refuse each semantic fault in it."""
        alias = b"copied alias"
        values = [
            (201, alias),
            (205, control.ALIAS_205),
            (206, control.ALIAS_206),
            (213, control.ALIAS_213),
            (207, b"\x01\x4d"),
        ]

        def frame(items: list[tuple[int, bytes]]) -> dict[str, typ.Any]:
            """Build one reply frame of request 13 carrying the given fields.

            Returns
            -------
            dict[str, typing.Any]
                The decoded reply frame.
            """
            return reply(13, items)

        field_207 = control.positive_alias(frame(values), alias)["field207_hex"]
        assert field_207 == "014d", "field 207 of the tagged reply"
        changes = [
            ([(201, alias), (205, b"U54T"), *values[2:]], NOT_IDENTIFIED),
            ([(201, alias), (205, b"Unattached Alias"), *values[2:]], NOT_IDENTIFIED),
            ([*values, (205, control.ALIAS_205)], "Unexpected repeated scalar field"),
            ([(201, b"other"), *values[1:]], NOT_IDENTIFIED),
            ([*values[:2], (206, b"BAD!"), *values[3:]], NOT_IDENTIFIED),
        ]
        for changed, message in changes:
            with pytest.raises(ValueError, match=re.escape(message)):
                control.positive_alias(frame(changed), alias)
        error = frame(values)
        error["error"] = 1
        with pytest.raises(ValueError, match="status/error"):
            control.direct([error], 13)
        with pytest.raises(ValueError, match="duplicate"):
            control.direct([frame(values), frame(values)], 13)

    def test_owned_target_and_finder_bytes(self) -> None:
        """Compare the owned target and its Finder sidecar bytes and metadata."""
        with tempfile.TemporaryDirectory() as temp:
            runtime = Path(temp) / "native-alias-live-05"
            shared = runtime / "shared"
            (shared / ".finf").mkdir(parents=True)
            target = shared / cases.TARGET.decode()
            finder = shared / ".finf" / cases.TARGET.decode()
            target.write_bytes(cases.TARGET_DATA)
            finder.write_bytes(b"U54TM54X" + bytes(24))
            target.chmod(0o600)
            finder.chmod(0o600)
            seconds = target.stat().st_mtime_ns // 1_000_000_000
            os.utime(
                target,
                ns=(seconds * 1_000_000_000, seconds * 1_000_000_000 + 88_000_000),
            )
            plan = cases.source_plan({
                **ENV,
                "owned_runtime": str(runtime),
                "owned_working_image": str(runtime / "working.dsk"),
            })
            before = control.host_state(plan)
            os.utime(target, ns=(seconds * 1_000_000_000, seconds * 1_000_000_000))
            changed = bytearray(finder.read_bytes())
            changed[10] = 1
            finder.write_bytes(changed)
            after = control.host_state(plan)
            assert before["target"]["mtime_ns"] != after["target"]["mtime_ns"], (
                "target mtime differs"
            )
            control.same_target(before, after)
            assert before["finder"]["sha256"] != after["finder"]["sha256"], (
                "finder digest differs"
            )
            changed[0] = ord("X")
            finder.write_bytes(changed)
            with pytest.raises(ValueError, match="type/creator"):
                control.host_state(plan)
            finder.write_bytes(b"U54TM54X" + bytes(24))
            target.write_bytes(b"X" + cases.TARGET_DATA[1:])
            with pytest.raises(ValueError, match="DATA differs"):
                control.host_state(plan)
            target.write_bytes(cases.TARGET_DATA)
            target.unlink()
            with pytest.raises(FileNotFoundError, match="No such file or directory"):
                control.host_state(plan)

    def test_duplicate_200_rows_stop_before_206(self) -> None:
        """Stop before the 206 when the file list repeats a name."""

        def fake_exchange(
            wire: FakeWire, spec: dict[str, typ.Any], alias: bytes | None = None
        ) -> dict[str, typ.Any]:
            """Count one exchange and return the next scripted reply.

            Returns
            -------
            dict[str, typing.Any]
                The next reply of the script.
            """
            wire.request_count += 1
            return next(remaining)

        with tempfile.TemporaryDirectory() as temp:
            receipt = Path(temp) / "receipt.json"
            receipt.write_text(
                json.dumps(cases.example_operator_receipt()), encoding="utf-8"
            )
            plan = cases.source_plan(ENV)
            host = {
                "parents": {},
                "target": {},
                "finder": {"sha256": control.digest(b"U54TM54X" + bytes(24))},
            }
            original_digest = control.digest
            roots = [(200, row(f"prior-{i}".encode())) for i in range(41)]
            responses = [
                reply(10, []),
                reply(11, [*roots, (200, row(cases.ROOT))]),
                reply(12, [(200, row(b"copied alias"))] * 2),
            ]
            remaining = iter(responses)
            output = io.StringIO()
            with (
                mock.patch.object(control, "host_state", return_value=host),
                mock.patch.object(control, "check_screens"),
                mock.patch.object(control, "same_target"),
                mock.patch.object(
                    control,
                    "digest",
                    side_effect=lambda raw: (
                        control.AGREEMENT_SHA if raw == b"x" else original_digest(raw)
                    ),
                ),
                mock.patch.object(
                    control, "exchange", side_effect=fake_exchange
                ) as calls,
                contextlib.redirect_stdout(output),
                pytest.raises(ValueError, match="Repeated file-list name"),
            ):
                control.perform(
                    typ.cast("control.Wire", FakeWire()), plan, receipt, lambda: None
                )
            assert calls.call_count == 3, "206 was sent after ambiguity"
            ready = json.loads(output.getvalue())
            assert ready["event"] == "READY", "ready event"
            assert ready["stage"] == "awaiting-reviewed-Finder-receipt", "ready stage"
            assert ready["numbered_requests"] == 3, "numbered requests before stop"
            assert ready["plan_sha256"] == control.digest(
                (json.dumps(plan, indent=2) + "\n").encode()
            ), "plan digest in the ready event"
            assert ready["emulator_pid"] == ENV["emulator_pid"], "emulator pid"
            assert ready["emulator_netns_inode"] == ENV["emulator_netns_inode"], (
                "emulator namespace"
            )
            early = io.StringIO()
            with (
                mock.patch.object(control, "host_state", return_value=host),
                mock.patch.object(
                    control,
                    "digest",
                    side_effect=lambda raw: (
                        control.AGREEMENT_SHA if raw == b"x" else original_digest(raw)
                    ),
                ),
                mock.patch.object(
                    control, "exchange", side_effect=[reply(10, []), reply(11, [])]
                ) as calls,
                contextlib.redirect_stdout(early),
                pytest.raises(ValueError, match="Owned Files folder/root count"),
            ):
                control.perform(
                    typ.cast("control.Wire", FakeWire()), plan, receipt, lambda: None
                )
            assert not early.getvalue(), "no ready event before the count check"
            assert calls.call_count == 2, "two requests before the count check"

    def test_failed_run_writes_partial_report_and_closes_real_fd(
        self, tmp_path: Path
    ) -> None:
        """Write a partial report on failure and close the real socket."""
        runtime = tmp_path / "native-alias-live-05"
        stage_owned_files(runtime)
        env = {
            **ENV,
            "owned_runtime": str(runtime),
            "owned_working_image": str(runtime / "working.dsk"),
            "emulator_netns_inode": Path("/proc/self/ns/net").stat().st_ino,
            "initial_finf_sha256": cases.digest(PRESTAGED_FINFO),
        }
        folder = tmp_path / "plan"
        cases.write_plan(folder, env)
        receipt = tmp_path / "capture-ready.json"
        deadline = dt.datetime.now(dt.UTC) + dt.timedelta(seconds=600)
        receipt.write_text(
            json.dumps({
                "deadline_utc": deadline.isoformat(),
                "emulator_pid": env["emulator_pid"],
            }),
            encoding="utf-8",
        )
        binary = tmp_path / "pef"
        binary.write_bytes(b"offline test oracle")
        owned_fd = []

        def fail_with_partial(
            wire: control.Wire,
            plan: dict[str, typ.Any],
            operator: Path,
            guard: object,
        ) -> None:
            """Leave a partial reply on the real socket, then fail.

            Raises
            ------
            ValueError
                Always, after the partial reply has been recorded.
            """
            left, right = socket.socketpair()
            owned_fd.append(left)
            wire.recorder.sockets["main"] = left
            wire.buffers["main"] = bytearray()
            wire.partial = {
                "stage": "partial-reply",
                "request_count": 2,
                "host_before": control.host_state(plan),
            }
            right.sendall(b"\x00\x01\x02")
            right.shutdown(socket.SHUT_WR)
            right.close()
            message = "controlled partial failure"
            raise ValueError(message)

        with (
            mock.patch.object(control, "runtime_gate"),
            mock.patch.object(
                control, "ORACLE_SHA256", control.digest(binary.read_bytes())
            ),
            mock.patch.object(control, "perform", fail_with_partial),
        ):
            report = control.run(
                folder,
                receipt,
                tmp_path / "operator.json",
                binary,
                tmp_path / "out",
            )
        assert report["status"] == "failed", "failed status"
        assert "controlled partial failure" in report["error"], "error text"
        assert report["stage"] == "partial-reply", "stage of the partial reply"
        assert report["unparsed_hex"]["main"] == "000102", "unparsed bytes"
        assert report["terminals"]["main"] == "eof", "terminal state"
        assert owned_fd[0].fileno() == -1, "the real socket is closed"
        written = (tmp_path / "out/report.json").read_text(encoding="utf-8")
        assert json.loads(written) == report, "report file matches the returned report"
        wrong = tmp_path / "wrong-plan"
        cases.write_plan(
            wrong, {**env, "initial_finf_sha256": ENV["initial_finf_sha256"]}
        )
        with (
            mock.patch.object(control, "runtime_gate"),
            mock.patch.object(
                control, "ORACLE_SHA256", control.digest(binary.read_bytes())
            ),
            pytest.raises(ValueError, match="Pre-socket Finder sidecar"),
        ):
            control.run(
                wrong,
                receipt,
                tmp_path / "operator.json",
                binary,
                tmp_path / "wrong-out",
            )
        assert not (tmp_path / "wrong-out").exists(), "no output for a refused run"

    def test_operator_gate_rejects_ambiguity(self) -> None:
        """Accept the example receipt and refuse each ambiguous change to it."""
        receipt = cases.example_operator_receipt()
        control.operator_gate(receipt, cases.source_plan(ENV))
        for key, value, message in (
            ("make_alias_enabled", False, GATE_DIFFERS),
            ("copy_enabled", False, GATE_DIFFERS),
            ("paste_enabled", False, GATE_DIFFERS),
            ("separate_alias", False, GATE_DIFFERS),
            ("unexpected_prompt", True, GATE_DIFFERS),
            ("overwrite_prompt", True, GATE_DIFFERS),
            ("action_count", 2, GATE_DIFFERS),
            ("target_name_hex", "00", "Operator target/destination differs"),
        ):
            changed = {**receipt, key: value}
            with pytest.raises(ValueError, match=re.escape(message)):
                control.operator_gate(changed, cases.source_plan(ENV))

    def test_operator_screenshots_must_match_bytes(self) -> None:
        """Refuse screenshots whose bytes differ from the receipt's digests."""
        receipt = cases.example_operator_receipt()
        with tempfile.TemporaryDirectory() as temp:
            screens = Path(temp) / "screens"
            screens.mkdir()
            for key in control.SCREEN_KEYS:
                (screens / f"{key}.png").write_bytes(b"not the claimed PNG")
            with pytest.raises(ValueError, match="screenshot differs"):
                control.check_screens(receipt, Path(temp))
