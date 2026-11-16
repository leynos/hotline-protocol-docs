"""Test that every verifier of a capture driver accepts the new identity form.

Decision D31 lets a verifier accept either the single-file hash that a capture
recorded before the decision or the identity record of one made after it. A
verifier does that with one call of ``capture_acceptance.driver_in`` or
``driver_is`` in place of its own comparison, so its checks stay in order. These
tests read the scripts as text: a verifier that compares
``report["driver_sha256"]`` itself would accept only the earlier form, so it must
be named below with the reason.
"""

import re
from pathlib import Path

SCRIPTS = Path(__file__).resolve().parents[1] / "scripts"
COMPARISON = re.compile(r"\[\"driver_sha256\"\]\s*(?:in|==)\s")

# Each verifier that still compares the single-file hash itself, and why.
EXEMPT = {
    "capture_acceptance.py": "the shared function that makes the comparison",
    "verify_native_repeat_runs.py": "compares with the constant of two retained runs",
    "verify_native_ui_focus_capture.py": "compares with the constant of one run",
    "verify_native_settings_persistence.py": "settings family, pending its own change",
    "verify_native_diagnostic_load.py": "reads the cleanup hash its planner writes",
}


def comparing() -> list[str]:
    """List the scripts that compare a report's ``driver_sha256`` themselves.

    Returns
    -------
    list[str]
        File names, sorted.
    """
    return sorted(
        path.name
        for path in SCRIPTS.glob("*.py")
        if COMPARISON.search(path.read_text(encoding="utf-8"))
    )


def test_only_the_named_verifiers_compare_the_single_file_hash_themselves() -> None:
    """Every other verifier goes through ``driver_in`` or ``driver_is``."""
    assert comparing() == sorted(EXEMPT), "expected only the named verifiers"


def test_each_exemption_still_compares_the_hash() -> None:
    """A verifier that was brought to the shared call leaves the list."""
    stale = sorted(set(EXEMPT) - set(comparing()))
    assert not stale, f"remove from EXEMPT: {stale}"


def test_the_verifiers_that_call_the_shared_function_import_it() -> None:
    """A call without its import would be a name error at verification time."""
    wrong = []
    for path in sorted(SCRIPTS.glob("verify_*.py")):
        text = path.read_text(encoding="utf-8")
        for name in ("driver_in", "driver_is"):
            called = re.search(rf"\b{name}\(", text)
            imported = re.search(
                rf"^from capture_acceptance import .*\b{name}\b", text, re.MULTILINE
            )
            multiline = re.search(
                rf"^from capture_acceptance import \((?:[^)]*)\b{name}\b",
                text,
                re.MULTILINE,
            )
            if called and not (imported or multiline):
                wrong.append(f"{path.name}: {name}")
    assert not wrong, f"missing import: {wrong}"
