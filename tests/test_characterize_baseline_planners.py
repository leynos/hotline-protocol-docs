"""Characterize the shared command line and identity check of two planners.

``native_settings_transition_cases`` and ``native_121_default_cases`` prepare an
observation between two copies of the A7 baseline plan, and share their command
line and their refusal of a runtime record that is not the baseline's. Every
expectation was observed on the two modules at their pinned commits
(``scripts/pinned-sources.json``) and must hold on the refactored modules;
``tests/test_pin_equivalence.py`` runs these tests against both. The usage text
of a command line that cannot be used is not pinned, only its exit status.
"""

import hashlib
import json
import sys
import typing as typ
from pathlib import Path

import native_121_default_cases
import native_settings_transition_cases
import pytest

if typ.TYPE_CHECKING:
    import types

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PLAN = (
    ROOT / "evidence/gap-remediation/2026-11-13/native-diagnostic-existing-preflight-01"
    "/capture/plan.json"
)
USAGE_STATUS = 2
IDENTITY_KEYS = ["oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap"]
PLANNERS = {
    "transition": (
        native_settings_transition_cases,
        "0b2107d020889007d0fce2f340039dad49620bcebc2b790f91b79a40c97562af",
        "fa9a06284ecefb674ff5524abb5c0561c21100f5e994fc59e1a800d1bd82c242",
    ),
    "121-default": (
        native_121_default_cases,
        "cb3e776bb526ec440f40e09386240e5763c420ee969fcdf9eee8c0362d5d3142",
        "c1373cc5d30a42a124fbc7f331dec09974ce44b7a31230d3b0c2af640486757c",
    ),
}
type Planner = tuple[types.ModuleType, str, str]


@pytest.fixture(scope="module")
def raw() -> bytes:
    """Read the retained baseline plan.

    Returns
    -------
    bytes
        The plan's bytes.
    """
    return BASELINE_PLAN.read_bytes()


@pytest.fixture(params=sorted(PLANNERS))
def planner(request: pytest.FixtureRequest) -> Planner:
    """Select one planner.

    Returns
    -------
    tuple[types.ModuleType, str, str]
        The module, the fingerprint of the directory it writes and the digest of
        its observation plan.
    """
    return PLANNERS[request.param]


def argv(
    monkeypatch: pytest.MonkeyPatch, runtime: Path, baseline: Path, output: Path
) -> None:
    """Set the command line of a run."""
    arguments = [
        "planner.py",
        "--runtime-record",
        str(runtime),
        "--baseline-plan",
        str(baseline),
        "--output",
        str(output),
    ]
    monkeypatch.setattr(sys, "argv", arguments)


@pytest.fixture
def record(tmp_path: Path, raw: bytes) -> Path:
    """Write the runtime record of the baseline.

    Returns
    -------
    pathlib.Path
        The record's path.
    """
    path = tmp_path / "runtime.json"
    path.write_text(json.dumps(json.loads(raw)["environment"]))
    return path


class IdentityTests:
    """The runtime record must carry the baseline's identity."""

    @pytest.mark.parametrize("key", IDENTITY_KEYS)
    def test_each_identity_key_is_compared(
        self, planner: Planner, raw: bytes, key: str
    ) -> None:
        """A record that differs in one of the four keys is refused."""
        runtime = dict(json.loads(raw)["environment"], **{key: "other"})
        message = r"^Runtime identity differs from pinned A7 baseline$"
        with pytest.raises(ValueError, match=message):
            planner[0].plans(runtime, raw)

    def test_an_empty_record_is_refused(self, planner: Planner, raw: bytes) -> None:
        """Every key is absent, which is not equal to the baseline's value."""
        with pytest.raises(ValueError, match=r"^Runtime identity differs"):
            planner[0].plans({}, raw)

    def test_other_runtime_fields_may_differ(
        self, planner: Planner, raw: bytes
    ) -> None:
        """Only the four identity fields are compared; the record is embedded."""
        runtime = dict(json.loads(raw)["environment"], note="extra")
        observed = planner[0].plans(runtime, raw)["observe"]
        assert observed["environment"]["note"] == "extra", "expected the record kept"

    def test_the_baseline_is_checked_before_the_runtime(
        self, planner: Planner, raw: bytes
    ) -> None:
        """Bad bytes with a bad runtime are a hash error."""
        with pytest.raises(ValueError, match=r"^A7 baseline input SHA-256 differs$"):
            planner[0].plans({"emulator_pid": -1}, raw + b" ")

    def test_the_baseline_is_its_own_preflight_and_postflight(
        self, planner: Planner, raw: bytes
    ) -> None:
        """Both flights are the parsed baseline, in the order of the output."""
        plans = planner[0].plans(json.loads(raw)["environment"], raw)
        assert list(plans) == ["preflight", "observe", "postflight"], "order"
        assert plans["preflight"] == json.loads(raw), "expected the baseline"
        assert plans["postflight"] == json.loads(raw), "expected the baseline"


class CommandLineTests:
    """``main`` reads the record and the baseline and writes three plans."""

    def test_three_plans_are_written_with_exact_bytes(
        self,
        planner: Planner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        record: Path,
    ) -> None:
        """The baseline bytes twice, and the observation as indented JSON."""
        module, directory, observation = planner
        raw = BASELINE_PLAN.read_bytes()
        output = tmp_path / "plans"
        argv(monkeypatch, record, BASELINE_PLAN, output)
        module.main()
        written = {
            path.name: hashlib.sha256(path.read_bytes()).hexdigest()
            for path in sorted(output.iterdir())
        }
        text = json.dumps(written).encode()
        assert hashlib.sha256(text).hexdigest() == directory, "expected the files"
        assert written["observe.json"] == observation, "expected the observation"
        baseline = hashlib.sha256(raw).hexdigest()
        assert written["preflight.json"] == baseline, "expected the baseline bytes"
        assert written["postflight.json"] == baseline, "expected the baseline bytes"

    def test_an_existing_output_is_refused_before_anything_is_read(
        self,
        planner: Planner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        record: Path,
    ) -> None:
        """Exit status 2, and the missing baseline is never opened."""
        output = tmp_path / "plans"
        output.mkdir()
        argv(monkeypatch, record, tmp_path / "absent.json", output)
        with pytest.raises(SystemExit) as caught:
            planner[0].main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"
        assert not list(output.iterdir()), "expected the directory untouched"

    @pytest.mark.parametrize("count", [0, 3])
    def test_a_missing_option_or_argument_exits_with_status_two(
        self, planner: Planner, monkeypatch: pytest.MonkeyPatch, count: int
    ) -> None:
        """Required options absent, or a stray positional argument."""
        monkeypatch.setattr(sys, "argv", ["planner.py", *["stray"] * count])
        with pytest.raises(SystemExit) as caught:
            planner[0].main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"

    def test_a_missing_baseline_fails_before_the_runtime_record_is_read(
        self, planner: Planner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The baseline is opened first, and no output directory is made."""
        output = tmp_path / "plans"
        argv(monkeypatch, tmp_path / "no-runtime.json", tmp_path / "no.json", output)
        with pytest.raises(FileNotFoundError) as caught:
            planner[0].main()
        assert caught.value.filename == str(tmp_path / "no.json"), "expected baseline"
        assert not output.exists(), "expected no output directory"

    def test_a_missing_runtime_record_fails_without_an_output_directory(
        self, planner: Planner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """With the baseline present, the runtime record is read next."""
        output = tmp_path / "plans"
        argv(monkeypatch, tmp_path / "no-runtime.json", BASELINE_PLAN, output)
        with pytest.raises(FileNotFoundError) as caught:
            planner[0].main()
        assert caught.value.filename == str(tmp_path / "no-runtime.json"), "runtime"
        assert not output.exists(), "expected no output directory"

    def test_a_runtime_that_differs_leaves_no_output_directory(
        self,
        planner: Planner,
        monkeypatch: pytest.MonkeyPatch,
        tmp_path: Path,
        raw: bytes,
    ) -> None:
        """The plans are prepared before the directory is created."""
        runtime = dict(json.loads(raw)["environment"], emulator_pid=-1)
        record = tmp_path / "runtime.json"
        record.write_text(json.dumps(runtime))
        output = tmp_path / "plans"
        argv(monkeypatch, record, BASELINE_PLAN, output)
        with pytest.raises(ValueError, match="Runtime identity differs"):
            planner[0].main()
        assert not output.exists(), "expected no output directory"
