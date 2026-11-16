"""Characterize the command line of ``native_control_readiness``.

This is the state before it is refactored.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module;
``tests/test_pin_equivalence.py`` runs these tests against both. No socket is
opened and no capture is run.
"""

import json
import os
import sys
import typing as typ

import native_ban_control_cases as cases
import native_control_readiness as gates
import pytest
from native_ban_control_cases import A7_SHA

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path

    from native_control_support import Report

RUNTIME = {"source_a7_sha256": A7_SHA, "emulator_pid": 42}
USAGE_STATUS = 2
STAGE_ORDER = [
    "require_controller_uid",
    "capture_gate",
    "plan_gate",
    "capture_gate",
    "run_plan",
    "gate-readiness",
    "capture_gate",
    "run_plan",
    "gate-guarded_account",
    "capture_gate",
    "run_plan",
    "gate-guarded_account",
    "capture_gate",
    "ban",
    "gate-outcome",
    "capture_gate",
    "run_plan",
    "gate-probe",
]


def written(tmp_path: Path) -> Path:
    """Write the five plans and their digests.

    Returns
    -------
    pathlib.Path
        The plan directory.
    """
    directory = tmp_path / "plans"
    hashes = cases.write_plans(directory, RUNTIME, 15750)
    (directory / "source-hashes.json").write_text(json.dumps(hashes))
    return directory


def arguments(*words: str) -> list[str]:
    """Build an argument vector for the script.

    Returns
    -------
    list[str]
        The program name and the words.
    """
    return ["native_control_readiness.py", *words]


class CommandLineTests:
    """The ``prepare`` and ``run`` commands."""

    @pytest.mark.parametrize(
        "words",
        [
            [],
            ["other"],
            ["prepare"],
            ["prepare", "--port", "15750", "--output", "o"],
            ["prepare", "--runtime-record", "r", "--output", "o"],
            ["prepare", "--runtime-record", "r", "--port", "x", "--output", "o"],
            ["run"],
            ["run", "--plans", "p", "--binary", "b", "--output", "o"],
        ],
    )
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, words: list[str]
    ) -> None:
        """No command, an unknown one, or a command without an option."""
        monkeypatch.setattr(sys, "argv", arguments(*words))
        with pytest.raises(SystemExit) as caught:
            gates.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"

    def test_prepare_writes_the_plans_and_their_digests(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The same files as ``write_plans`` makes, and ``source-hashes.json``."""
        record = tmp_path / "runtime.json"
        record.write_text(json.dumps(RUNTIME))
        output = tmp_path / "plans"
        words = ["prepare", "--runtime-record", str(record)]
        words += ["--port", "15750", "--output", str(output)]
        monkeypatch.setattr(sys, "argv", arguments(*words))
        gates.main()
        expected = cases.write_plans(tmp_path / "reference", RUNTIME, 15750)
        hashes = json.loads((output / "source-hashes.json").read_text())
        assert hashes == expected, "expected the digests of write_plans"
        for name in expected:
            assert (output / f"{name}.json").read_bytes() == (
                tmp_path / "reference" / f"{name}.json"
            ).read_bytes(), name
        text = (output / "source-hashes.json").read_text()
        assert text == json.dumps(expected, indent=2) + "\n", "expected the layout"

    def test_run_refuses_a_user_who_is_not_root_before_the_receipt_is_read(
        self, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        """The first step of a live run."""
        words = ["run", "--plans", "/p", "--binary", "/b"]
        words += ["--capture-ready", "/c", "--output", "/o"]
        monkeypatch.setattr(sys, "argv", arguments(*words))
        monkeypatch.setattr(os, "geteuid", lambda: 1000)
        with pytest.raises(PermissionError, match="requires root"):
            gates.main()

    def test_run_gates_every_stage_in_order(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The checks, the stage runs and the gates, in the order they occur."""
        log: list[tuple[object, ...]] = []
        receipt = tmp_path / "ready.json"
        receipt.write_text(json.dumps({"emulator_pid": 7}))
        plans = tmp_path / "plans"
        plans.mkdir()
        for name in ("readiness", "guard", "seed", "ban", "probe"):
            (plans / f"{name}.json").write_text(
                json.dumps({"environment": {"emulator_pid": 7}})
            )

        def record(label: str) -> cabc.Callable[..., Report]:
            """Make a stand-in that logs its call and returns a report named for it.

            Returns
            -------
            collections.abc.Callable[..., dict[str, typing.Any]]
                The stand-in.
            """

            def stand_in(*args: object, **kwargs: object) -> Report:
                """Log the call.

                Returns
                -------
                dict[str, typing.Any]
                    A report that names the stand-in.
                """
                numbers = [a for a in args if isinstance(a, (str, int))]
                log.append((label, *numbers, *kwargs.items()))
                return {"stage": label}

            return stand_in

        for name in ("require_controller_uid", "capture_gate", "plan_gate"):
            monkeypatch.setattr(gates, name, record(name))
        monkeypatch.setattr(
            gates, "run_plan", lambda plan, *_rest: record("run_plan")(plan.stem)
        )
        monkeypatch.setattr(
            gates, "run_guarded_ban", lambda plan, *_rest: record("ban")(plan.stem)
        )
        for name in ("readiness", "outcome", "probe", "guarded_account"):
            monkeypatch.setattr(gates, name, record(f"gate-{name}"))
        words = ["run", "--plans", str(plans), "--binary", "b"]
        words += ["--capture-ready", str(receipt), "--output", str(tmp_path / "out")]
        monkeypatch.setattr(sys, "argv", arguments(*words))
        gates.main()
        assert [entry[0] for entry in log] == STAGE_ORDER, log
        assert (tmp_path / "out").is_dir(), "expected the output directory"

    def test_a_plan_of_another_emulator_stops_a_stage_before_it_runs(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The plan's PID must be the receipt's."""
        receipt = tmp_path / "ready.json"
        receipt.write_text(json.dumps({"emulator_pid": 7}))
        plans = tmp_path / "plans"
        plans.mkdir()
        (plans / "readiness.json").write_text(
            json.dumps({"environment": {"emulator_pid": 8}})
        )
        ran: list[str] = []
        monkeypatch.setattr(gates, "require_controller_uid", lambda: None)
        monkeypatch.setattr(gates, "capture_gate", lambda _r: None)
        monkeypatch.setattr(gates, "plan_gate", lambda *_a: None)
        monkeypatch.setattr(gates, "run_plan", lambda *_a: ran.append("run"))
        words = ["run", "--plans", str(plans), "--binary", "b"]
        words += ["--capture-ready", str(receipt), "--output", str(tmp_path / "out")]
        monkeypatch.setattr(sys, "argv", arguments(*words))
        with pytest.raises(ValueError, match=r"^Plan/actual emulator PID mismatch$"):
            gates.main()
        assert not ran, "expected no stage to run"
