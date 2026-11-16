"""Characterize the baseline checks and command line of ``native_pm_cases``.

Every expectation was observed on the module at its pinned commit
(``scripts/pinned-sources.json``) and must hold on the refactored module. Each
check of the baseline plan has one synthetic fault, and pairs of faults pin which
error is raised first. The usage text of the command line is not pinned, only
its exit status. The builders are in ``test_characterize_native_pm_cases.py``.
"""

import json
import sys
import typing as typ
from pathlib import Path

import native_pm_cases as cases
import pytest

if typ.TYPE_CHECKING:
    import collections.abc as cabc

CHARACTERIZES = "native_pm_cases.py"
ROOT = Path(__file__).resolve().parents[1]
BASELINE_PLAN = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
IDENTITY_KEYS = ("oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap")


@pytest.fixture(scope="module")
def raw() -> bytes:
    """Read the retained baseline plan.

    Returns
    -------
    bytes
        The plan's bytes.
    """
    return BASELINE_PLAN.read_bytes()


@pytest.fixture
def baseline(raw: bytes) -> dict[str, typ.Any]:
    """Parse the retained baseline plan afresh for each test.

    Returns
    -------
    dict[str, typing.Any]
        A private copy of the plan.
    """
    return json.loads(raw)


def refused(plan: dict[str, typ.Any], message: str) -> None:
    """Require that the structure check raises a ``ValueError`` with this message."""
    with pytest.raises(ValueError, match=f"^{message}$"):
        cases.check_baseline_structure(plan)


class BaselineStructureTests:
    """Each check of the baseline plan, and the order of the checks."""

    def test_the_retained_baseline_passes(self, baseline: dict[str, typ.Any]) -> None:
        """No error for the plan as retained."""
        cases.check_baseline_structure(baseline)

    def test_an_invalid_plan_is_refused_by_the_capture_validator_first(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """An unknown profile is the validator's error, not the oracle one."""
        baseline["profile"] = "bogus"
        refused(baseline, "Unknown evidence profile")

    def test_another_profile_is_a_different_oracle_identity(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """A valid synthetic profile is not the native oracle."""
        baseline["profile"] = "synthetic-tool-test"
        refused(baseline, "A7 baseline oracle identity differs")

    def test_another_oracle_hash_under_the_native_profile_is_the_validators(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """The validator rejects the hash before the identity check sees it."""
        baseline["oracle_sha256"] = "0" * 64
        refused(baseline, "Native profile requires the recorded Mac oracle hash")

    def test_a_changed_expectation_is_refused(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """Any difference in the expectation dictionary."""
        baseline["expectation"]["expected_stream_bytes"] += 1
        refused(baseline, "A7 baseline full-fork expectation differs")

    def test_an_extra_expectation_key_is_refused(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """The dictionary must match exactly."""
        baseline["expectation"]["extra"] = 1
        refused(baseline, "A7 baseline full-fork expectation differs")

    def test_a_plan_without_an_expectation_is_a_key_error(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """The expectation is read by key."""
        del baseline["expectation"]
        with pytest.raises(KeyError, match="expectation"):
            cases.check_baseline_structure(baseline)

    def test_a_short_plan_has_the_wrong_shape(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """Fewer than 29 steps."""
        baseline["steps"] = baseline["steps"][:-1]
        refused(baseline, "A7 baseline full 29-step/data-endpoint shape differs")

    def test_other_endpoints_have_the_wrong_shape(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """The control and data endpoints are fixed."""
        baseline["endpoints"]["data"]["port"] = 15502
        refused(baseline, "A7 baseline full 29-step/data-endpoint shape differs")

    def test_the_expectation_check_comes_before_the_shape_check(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """A plan wrong in both is reported for the expectation."""
        baseline["expectation"]["expected_stream_bytes"] += 1
        baseline["steps"] = baseline["steps"][:-1]
        refused(baseline, "A7 baseline full-fork expectation differs")

    @pytest.mark.parametrize(
        "change",
        [
            lambda steps: steps[19].update(timeout=11),
            lambda steps: steps[19].update(endpoint="control"),
            lambda steps: steps[21].update(size=cases.FULL_STREAM_BYTES - 1),
            lambda steps: steps[24].update(op="expect_quiet"),
        ],
        ids=["step-19-timeout", "step-19-endpoint", "step-21-size", "step-24-op"],
    )
    def test_a_changed_download_step_is_refused(
        self,
        baseline: dict[str, typ.Any],
        change: cabc.Callable[[list[dict[str, typ.Any]]], object],
    ) -> None:
        """Steps 19, 21 and 24 are compared with the recorded sequence."""
        change(baseline["steps"])
        refused(baseline, "A7 baseline full download sequence differs")

    def test_the_shape_check_comes_before_the_download_check(
        self, baseline: dict[str, typ.Any]
    ) -> None:
        """A plan with another endpoint and another step 21 is a shape error."""
        baseline["endpoints"]["data"]["port"] = 15502
        baseline["steps"][21]["size"] = 1
        refused(baseline, "A7 baseline full 29-step/data-endpoint shape differs")


class LoadAndPlansTests:
    """Loading the baseline bytes and preparing the three plans."""

    def test_a_changed_byte_is_refused_by_hash_before_it_is_parsed(
        self, raw: bytes
    ) -> None:
        """The hash is checked first, so unparsable bytes are a hash error."""
        for data in (raw + b" ", b"{", b""):
            with pytest.raises(
                ValueError, match=r"^A7 baseline input SHA-256 differs$"
            ):
                cases.load_baseline(data)

    def test_the_retained_bytes_load_as_the_parsed_plan(self, raw: bytes) -> None:
        """The loaded plan is the JSON of the bytes."""
        assert cases.load_baseline(raw) == json.loads(raw), "expected the parse"

    @pytest.mark.parametrize("key", IDENTITY_KEYS)
    def test_each_identity_field_of_the_runtime_must_match_the_baseline(
        self, raw: bytes, key: str
    ) -> None:
        """A changed or absent field is a runtime identity error."""
        runtime = dict(json.loads(raw)["environment"])
        runtime[key] = "changed"
        with pytest.raises(ValueError, match=r"^Runtime identity differs"):
            cases.plans(runtime, raw)
        del runtime[key]
        with pytest.raises(ValueError, match=r"^Runtime identity differs"):
            cases.plans(runtime, raw)

    def test_other_runtime_fields_may_differ(self, raw: bytes) -> None:
        """Only the four identity fields are compared."""
        runtime = dict(json.loads(raw)["environment"], note="extra")
        observed = cases.plans(runtime, raw)["observe"]
        assert observed["environment"]["note"] == "extra", "expected the runtime kept"

    def test_the_baseline_is_checked_before_the_runtime(self, raw: bytes) -> None:
        """Bad bytes with a bad runtime are a hash error."""
        with pytest.raises(ValueError, match=r"^A7 baseline input SHA-256 differs$"):
            cases.plans({"emulator_pid": -1}, raw + b" ")


class CommandLineTests:
    """``main`` reads its arguments from ``sys.argv``."""

    @staticmethod
    def argv(
        monkeypatch: pytest.MonkeyPatch, runtime: Path, baseline: Path, output: Path
    ) -> None:
        """Set the command line of a run."""
        arguments = [
            CHARACTERIZES,
            "--runtime-record",
            str(runtime),
            "--baseline-plan",
            str(baseline),
            "--output",
            str(output),
        ]
        monkeypatch.setattr(sys, "argv", arguments)

    @pytest.fixture
    def record(self, tmp_path: Path, raw: bytes) -> Path:
        """Write the runtime record of the baseline.

        Returns
        -------
        pathlib.Path
            The record's path.
        """
        path = tmp_path / "runtime.json"
        path.write_text(json.dumps(json.loads(raw)["environment"]))
        return path

    def test_three_plans_are_written_in_order_with_exact_bytes(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record: Path, raw: bytes
    ) -> None:
        """The baseline bytes twice, and the observation as indented JSON."""
        output = tmp_path / "plans"
        self.argv(monkeypatch, record, BASELINE_PLAN, output)
        cases.main()
        assert sorted(p.name for p in output.iterdir()) == [
            "observe.json",
            "postflight.json",
            "preflight.json",
        ], "expected three plans"
        assert (output / "preflight.json").read_bytes() == raw, "preflight bytes"
        assert (output / "postflight.json").read_bytes() == raw, "postflight bytes"
        observed = cases.plans(json.loads(raw)["environment"], raw)["observe"]
        expected = (json.dumps(observed, indent=2) + "\n").encode()
        assert (output / "observe.json").read_bytes() == expected, "observe bytes"

    def test_an_existing_output_is_refused_before_anything_is_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, record: Path
    ) -> None:
        """Exit status 2, and the missing baseline is never opened."""
        output = tmp_path / "plans"
        output.mkdir()
        self.argv(monkeypatch, record, tmp_path / "absent.json", output)
        with pytest.raises(SystemExit) as caught:
            cases.main()
        assert caught.value.code == 2, "expected the usage status"
        assert not list(output.iterdir()), "expected the directory untouched"

    @pytest.mark.parametrize("count", [0, 3])
    def test_a_missing_option_or_argument_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, count: int
    ) -> None:
        """Required options absent, or a stray positional argument."""
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *["stray"] * count])
        with pytest.raises(SystemExit) as caught:
            cases.main()
        assert caught.value.code == 2, "expected the usage status"

    def test_a_missing_baseline_fails_before_the_runtime_record_is_read(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The baseline is opened first, and no output directory is made."""
        output = tmp_path / "plans"
        self.argv(
            monkeypatch, tmp_path / "no-runtime.json", tmp_path / "no.json", output
        )
        with pytest.raises(FileNotFoundError) as caught:
            cases.main()
        assert caught.value.filename == str(tmp_path / "no.json"), "expected baseline"
        assert not output.exists(), "expected no output directory"

    def test_a_missing_runtime_record_fails_without_an_output_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """With the baseline present, the runtime record is read next."""
        output = tmp_path / "plans"
        self.argv(monkeypatch, tmp_path / "no-runtime.json", BASELINE_PLAN, output)
        with pytest.raises(FileNotFoundError) as caught:
            cases.main()
        assert caught.value.filename == str(tmp_path / "no-runtime.json"), "runtime"
        assert not output.exists(), "expected no output directory"

    def test_a_runtime_that_differs_leaves_no_output_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path, raw: bytes
    ) -> None:
        """The plans are prepared before the directory is created."""
        runtime = dict(json.loads(raw)["environment"], emulator_pid=-1)
        record = tmp_path / "runtime.json"
        record.write_text(json.dumps(runtime))
        output = tmp_path / "plans"
        self.argv(monkeypatch, record, BASELINE_PLAN, output)
        with pytest.raises(ValueError, match="Runtime identity differs"):
            cases.main()
        assert not output.exists(), "expected no output directory"
