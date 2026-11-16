"""Characterize ``native_settings_persistence_cases``, which stays at the old rules.

The planner records the SHA-256 of itself and of three sibling scripts in the
plans it writes (decision D31), so it is not refactored yet. These tests were
written on its current bytes. They pin its output so that a refactor of a script
that it embeds, such as ``native_ban_control_cases``, cannot change a plan: the
plans are fingerprinted, the order of its refusals is held, and its command line
is run against a runtime record.
"""

import hashlib
import json
import sys
import typing as typ

import native_settings_persistence_cases as cases
import pytest

if typ.TYPE_CHECKING:
    from pathlib import Path

CHARACTERIZES = "native_settings_persistence_cases.py"
RUNTIME = {"source_a7_sha256": cases.A7_SHA, "emulator_pid": 123}
BARRIER = "09678cd0d40a03d526a2692e29ac0a31794ca9d871859c9308521d0cb4e1c226"
AUTOMATIC = "ae0f921ad2cef01fb260c0b77ce8c31d2d5d0dd877aedfafea53d4fda4162c23"
PLAIN = "1dcf45288f16906d1dcf11f135addf9df28f8bfd47c580837b2f5292052173e7"
OBSERVATIONS = {
    1: (66, "fb9038e4ab297136dbb3ad450edae84c093de170a9fecc9215381648e451de0b"),
    2: (28, "1b7dd5be7d4bde45810a8381ca22ba2f187bf738ca6dbee1160f5c6f7304959d"),
}
PLANS = "2cc6b15defa693f30e63098e5c0afd56ff1bf90c2fbfaa82a059b5c618f4ef06"
OUTPUT = "8c9689dfd0e49ec6b82ca018ef42c79ecd8a9a05021c29480a13817ec19662b6"
SOURCE_NAMES = [
    "native_ban_control_cases.py",
    "native_control_readiness.py",
    "native_settings_persistence.py",
    "native_settings_persistence_cases.py",
]
USAGE_STATUS = 2


def fingerprint(value: object) -> str:
    """Hash the JSON text of a value, keys in their existing order.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(json.dumps(value).encode()).hexdigest()


class PlanTests:
    """The steps and plans, pinned by fingerprint."""

    def test_a_barrier_is_unchanged(self) -> None:
        """Both connections are ordered and checked quiet."""
        assert fingerprint(cases.barrier(100)) == BARRIER, "expected the same steps"

    def test_a_message_with_and_without_the_automatic_response(self) -> None:
        """The two forms of the observed message."""
        with_auto = cases.message(70, b"text", automatic=True)
        without = cases.message(71, b"text", automatic=False)
        assert fingerprint(with_auto) == AUTOMATIC, "expected the automatic form"
        assert fingerprint(without) == PLAIN, "expected the plain form"

    @pytest.mark.parametrize("phase", sorted(OBSERVATIONS))
    def test_each_observation_is_unchanged(self, phase: int) -> None:
        """The steps and the expectation of one phase."""
        count, expected = OBSERVATIONS[phase]
        steps, expectation = cases.observation(phase)
        assert len(steps) == count, "expected the step count"
        assert fingerprint([steps, expectation]) == expected, "expected the same plan"

    def test_the_three_plans_are_unchanged(self) -> None:
        """Both phases and the readiness plan, which reuses the ban control's."""
        built = cases.plans(RUNTIME, 15760)
        assert list(built) == ["phase1", "phase2", "readiness"], "plan order"
        assert fingerprint(built) == PLANS, "expected the same plans"


class RefusalTests:
    """The checks of ``plans`` and their order."""

    @pytest.mark.parametrize("runtime", [{}, {"source_a7_sha256": "other"}])
    def test_a_different_a7_hash_is_refused(self, runtime: dict[str, str]) -> None:
        """A missing or different original A7 hash."""
        with pytest.raises(ValueError, match=r"^A7 provenance differs$"):
            cases.plans(runtime, 15760)

    @pytest.mark.parametrize("port", [1023, 65533, 15500, 15501])
    def test_an_unsafe_port_is_refused(self, port: int) -> None:
        """Outside 1024 to 65532, or one of the primary bridge's ports."""
        with pytest.raises(ValueError, match=r"^Unsafe control endpoint$"):
            cases.plans(RUNTIME, port)

    @pytest.mark.parametrize("port", [1024, 65532])
    def test_the_ends_of_the_range_are_accepted(self, port: int) -> None:
        """Both ends are inclusive."""
        built = cases.plans(RUNTIME, port)
        assert list(built) == ["phase1", "phase2", "readiness"], "expected three"

    def test_the_source_hash_is_checked_before_the_port(self) -> None:
        """Both faults at once end with the source hash."""
        with pytest.raises(ValueError, match=r"^A7 provenance differs$"):
            cases.plans({}, 1)


class CommandLineTests:
    """``main`` writes the plans, their digests and the digests of four sources."""

    @staticmethod
    def argv(monkeypatch: pytest.MonkeyPatch, *arguments: str) -> None:
        """Set the command line of a run."""
        monkeypatch.setattr(sys, "argv", [CHARACTERIZES, *arguments])

    def test_the_plans_and_their_digests_are_written(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """Three plans, ``source-hashes.json`` and ``source-code-sha256.json``."""
        runtime = tmp_path / "runtime.json"
        runtime.write_text(json.dumps(RUNTIME))
        output = tmp_path / "plans"
        self.argv(
            monkeypatch,
            "--runtime",
            str(runtime),
            "--port",
            "15760",
            "--output",
            str(output),
        )
        cases.main()
        files = {
            p.name: hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted(output.iterdir())
        }
        assert sorted(files) == [
            "phase1.json",
            "phase2.json",
            "readiness.json",
            "source-code-sha256.json",
            "source-hashes.json",
        ], "expected five files"
        written = {k: v for k, v in files.items() if k != "source-code-sha256.json"}
        assert fingerprint(written) == OUTPUT, "expected the same plan bytes"
        sources = json.loads((output / "source-code-sha256.json").read_text())
        assert sorted(sources) == SOURCE_NAMES, "expected the four sibling sources"
        hashes = json.loads((output / "source-hashes.json").read_text())
        assert hashes == {
            name: files[f"{name}.json"] for name in ("phase1", "phase2", "readiness")
        }, "expected each plan's digest"

    @pytest.mark.parametrize(
        "arguments", [[], ["--runtime", "x"], ["--runtime", "x", "--port", "y"]]
    )
    def test_a_command_line_that_cannot_be_used_exits_with_status_two(
        self, monkeypatch: pytest.MonkeyPatch, arguments: list[str]
    ) -> None:
        """A missing option, or a port that is not a number."""
        self.argv(monkeypatch, *arguments)
        with pytest.raises(SystemExit) as caught:
            cases.main()
        assert caught.value.code == USAGE_STATUS, "expected the usage status"

    def test_an_existing_output_is_refused_after_the_plans_are_prepared(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The directory is made exclusively, after the record is checked."""
        runtime = tmp_path / "runtime.json"
        runtime.write_text(json.dumps(RUNTIME))
        output = tmp_path / "plans"
        output.mkdir()
        self.argv(
            monkeypatch,
            "--runtime",
            str(runtime),
            "--port",
            "15760",
            "--output",
            str(output),
        )
        with pytest.raises(FileExistsError):
            cases.main()

    def test_a_missing_runtime_record_leaves_no_output_directory(
        self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
    ) -> None:
        """The record is read before the directory is made."""
        output = tmp_path / "plans"
        record = tmp_path / "absent.json"
        self.argv(
            monkeypatch,
            "--runtime",
            str(record),
            "--port",
            "15760",
            "--output",
            str(output),
        )
        with pytest.raises(FileNotFoundError):
            cases.main()
        assert not output.exists(), "expected no output directory"
