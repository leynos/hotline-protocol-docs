"""Test that a pinned script's tests give the same outcomes under both versions.

The synthetic cases prove the check is not vacuous: an equivalent refactor
passes it and a behaviour change fails it. No pinned script differs from its
pinned bytes today, so the real-tree cases run the machinery on identical
bytes, which must also pass, and fail the build as soon as a script that
differs is not equivalent.
"""

import os
from pathlib import Path

import pin_equivalence
import pinned_source
import pytest

ROOT = Path(__file__).resolve().parents[1]
PINNED_CALC = b"def add(a, b):\n    return a + b\n"
TEST_CALC = (
    "import calc\n\n\n"
    "class CalcTests:\n"
    "    def test_adds(self):\n        assert calc.add(2, 3) == 5\n\n"
    "    def test_cancels(self):\n        assert calc.add(-1, 1) == 0\n"
)
WRAPPER = "import calc\n\n\ndef twice(x):\n    return calc.add(x, x)\n"
TEST_WRAPPER = (
    "import wrapper\n\n\nclass WrapperTests:\n"
    "    def test_twice(self):\n        assert wrapper.twice(4) == 8\n"
)
LONELY = "VALUE = 1\n"
EXPECTED_FAILURES = 3  # test_adds, test_cancels and the wrapper's test


def scripts_with(tmp_path: Path, calc: bytes) -> Path:
    """Build a small ``scripts/`` directory whose ``calc.py`` is ``calc``.

    Returns
    -------
    pathlib.Path
        The directory.
    """
    scripts = tmp_path / "scripts"
    (scripts / "tests").mkdir(parents=True)
    (scripts / "calc.py").write_bytes(calc)
    (scripts / "wrapper.py").write_text(WRAPPER)
    (scripts / "lonely.py").write_text(LONELY)
    (scripts / "tests/test_calc.py").write_text(TEST_CALC)
    (scripts / "tests/test_wrapper.py").write_text(TEST_WRAPPER)
    return scripts


class SyntheticEquivalenceTests:
    """A pinned and a current version of a small module, with two test files."""

    def test_tests_that_import_the_module_directly_or_not_are_selected(
        self, tmp_path: Path
    ) -> None:
        """A test of a module that wraps the script is reached too."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        found = pin_equivalence.reaching_tests(scripts, "calc.py")
        assert found == [
            "scripts/tests/test_calc.py",
            "scripts/tests/test_wrapper.py",
        ], "expected both test files"

    def test_an_equivalent_refactor_has_no_differences(self, tmp_path: Path) -> None:
        """Rewriting the sum another way leaves every outcome unchanged."""
        refactored = b"def add(a, b):\n    return sum((a, b))\n"
        scripts = scripts_with(tmp_path, refactored)
        found = pin_equivalence.differences(scripts, "calc.py", PINNED_CALC)
        assert found == [], "expected an equivalent refactor to pass"

    def test_a_behaviour_change_is_reported_test_by_test(self, tmp_path: Path) -> None:
        """An off-by-one fails three tests, each named with both outcomes."""
        changed = b"def add(a, b):\n    return a + b + 1\n"
        scripts = scripts_with(tmp_path, changed)
        found = pin_equivalence.differences(scripts, "calc.py", PINNED_CALC)
        assert len(found) == EXPECTED_FAILURES, "expected every reaching test to fail"
        assert all("pinned PASSED, current FAILED" in line for line in found), (
            "expected each line to name both outcomes"
        )

    def test_a_script_that_no_test_reaches_is_an_error(self, tmp_path: Path) -> None:
        """Equivalence cannot be shown without a test, so the check refuses."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        with pytest.raises(pin_equivalence.NoCoverageError, match=r"lonely\.py"):
            pin_equivalence.differences(scripts, "lonely.py", LONELY.encode())


TOP_LEVEL_TEST = (
    "import calc\n\n\n"
    "class TopLevelTests:\n"
    "    def test_adds_again(self):\n        assert calc.add(1, 1) == 2\n"
)
HYPHENATED = "def label():\n    return 'plain'\n"
HYPHENATED_TEST = (
    "import importlib.util\nfrom pathlib import Path\n\n"
    'CHARACTERIZES = "odd-name.py"\n\n\n'
    "class OddNameTests:\n"
    "    def test_label(self):\n"
    "        path = Path(__file__).resolve().parents[1] / 'scripts' / CHARACTERIZES\n"
    "        spec = importlib.util.spec_from_file_location('odd', path)\n"
    "        module = importlib.util.module_from_spec(spec)\n"
    "        spec.loader.exec_module(module)\n"
    "        assert module.label() == 'plain'\n"
)


class TopLevelTestEquivalenceTests:
    """Tests kept beside the repository tools are run under both versions."""

    def test_a_test_outside_scripts_tests_is_selected(self, tmp_path: Path) -> None:
        """A test file in ``tests/`` that imports the script is reached."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests/test_top.py").write_text(TOP_LEVEL_TEST)
        found = pin_equivalence.reaching_tests(scripts, "calc.py")
        assert "tests/test_top.py" in found, "expected the top-level test"

    def test_a_top_level_test_that_fails_under_the_change_is_reported(
        self, tmp_path: Path
    ) -> None:
        """An off-by-one is caught by a test that lives in ``tests/``."""
        scripts = scripts_with(tmp_path, b"def add(a, b):\n    return a + b + 1\n")
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests/test_top.py").write_text(TOP_LEVEL_TEST)
        found = pin_equivalence.differences(scripts, "calc.py", PINNED_CALC)
        assert any("tests/test_top.py" in line for line in found), (
            "expected the top-level test among the differences"
        )

    def test_a_script_loaded_by_its_hyphenated_name_is_reached(
        self, tmp_path: Path
    ) -> None:
        """A test that declares the hyphenated script it characterizes reaches it."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        (scripts / "odd-name.py").write_text(HYPHENATED)
        (tmp_path / "tests").mkdir()
        (tmp_path / "tests/test_odd.py").write_text(HYPHENATED_TEST)
        found = pin_equivalence.differences(scripts, "odd-name.py", HYPHENATED.encode())
        assert found == [], "expected the named script to be reached and agree"


class CompanionEquivalenceTests:
    """A verifier that hashes its siblings is compared with them pinned too."""

    def test_companion_bytes_are_swapped_into_the_pinned_copy_only(
        self, tmp_path: Path
    ) -> None:
        """A program that prints a sibling's text differs unless it is staged."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        (scripts / "reader.py").write_text(
            "from pathlib import Path\n"
            "print(Path(__file__).with_name('note.txt').read_text())\n"
        )
        (scripts / "note.txt").write_text("current\n")
        setting = pin_equivalence.Setting(
            program=[], companions={"note.txt": b"earlier\n"}
        )
        found = pin_equivalence.differences(
            scripts, "reader.py", (scripts / "reader.py").read_bytes(), setting
        )
        assert found == ["program run: pinned 'earlier', current 'current'"], (
            "expected only the companion to differ"
        )


HELLO = "print('hello')\n"


class ProgramEquivalenceTests:
    """A script that no test imports is compared by running it."""

    def test_an_equivalent_program_has_no_differences(self, tmp_path: Path) -> None:
        """The same output and exit code from both versions pass."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        (scripts / "hello.py").write_text('print("hello")\n')
        found = pin_equivalence.differences(
            scripts, "hello.py", HELLO.encode(), pin_equivalence.Setting(program=[])
        )
        assert found == [], "expected the same output to pass"

    def test_a_program_that_prints_something_else_is_reported(
        self, tmp_path: Path
    ) -> None:
        """A change in the output is a difference, named line by line."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        (scripts / "hello.py").write_text("print('goodbye')\n")
        found = pin_equivalence.differences(
            scripts, "hello.py", HELLO.encode(), pin_equivalence.Setting(program=[])
        )
        assert found == ["program run: pinned 'hello', current 'goodbye'"], (
            "expected the changed line"
        )

    def test_a_program_that_fails_is_reported(self, tmp_path: Path) -> None:
        """A change in the exit code is a difference."""
        scripts = scripts_with(tmp_path, PINNED_CALC)
        (scripts / "hello.py").write_text("raise SystemExit(3)\n")
        found = pin_equivalence.differences(
            scripts, "hello.py", b"", pin_equivalence.Setting(program=[])
        )
        assert found[0] == "program run: pinned 'exit code 0', current 'exit code 3'", (
            "expected the exit code to differ"
        )


def real_links() -> dict[str, Path]:
    """Link the evidence, documents and history, and mothra when set, into the copies.

    Returns
    -------
    dict[str, pathlib.Path]
        The links that the retained-corpus tests need.
    """
    links = {
        "evidence": ROOT / "evidence",
        "docs": ROOT / "docs",
        ".git": ROOT / ".git",  # the copies read pinned bytes from this history
    }
    if "MOTHRA_ROOT" in os.environ:
        links["mothra"] = Path(os.environ["MOTHRA_ROOT"])
    return links


# A verifier that hashes the scripts beside it finds them at their pinned bytes in
# the pinned copy, as its recorded hashes demand.
COMPANIONS = {
    "verify-baseline-evidence.py": [
        "capture-ghidra-evidence.py",
        "extract-synhxd-evidence.py",
    ]
}


def differing(pins: pinned_source.Pins) -> list[str]:
    """List the pinned scripts whose current bytes differ from their pinned bytes.

    Returns
    -------
    list[str]
        File names.
    """
    return [
        name
        for name in pins.names()
        if (ROOT / "scripts" / name).read_bytes() != pins.read(name)
    ]


CHANGED = differing(pinned_source.Pins())
EQUIVALENCE_SECONDS = 3600  # a widely imported script reruns most of the suite twice


class PinnedScriptEquivalenceTests:
    """Every pinned script that has changed must behave as it did when pinned."""

    @pytest.mark.pin_equivalence
    @pytest.mark.timeout(EQUIVALENCE_SECONDS)
    @pytest.mark.parametrize("name", CHANGED)
    def test_a_changed_script_passes_its_tests_under_both_versions(
        self, name: str
    ) -> None:
        """The tests that reach the script agree on its pinned and current bytes."""
        pins = pinned_source.Pins()
        found = pin_equivalence.differences(
            ROOT / "scripts",
            name,
            pins.read(name),
            pin_equivalence.Setting(
                real_links(),
                companions={n: pins.read(n) for n in COMPANIONS.get(name, [])},
            ),
        )
        assert found == [], f"{name} behaves differently from its pinned bytes"

    def test_the_machinery_runs_the_real_tests_of_an_identical_script(self) -> None:
        """On identical bytes the real tests agree and are not an empty set."""
        pins = pinned_source.Pins()
        name = "native_121_default_cases.py"
        tests = pin_equivalence.reaching_tests(ROOT / "scripts", name)
        assert tests, "expected a test to reach the script"
        found = pin_equivalence.differences(
            ROOT / "scripts",
            name,
            pins.read(name),
            pin_equivalence.Setting(real_links()),
        )
        assert found == [], "expected identical bytes to agree"
