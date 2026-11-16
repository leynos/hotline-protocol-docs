"""Load the frozen rate304 sources and check the identity of the retained run.

The frozen copies are the ones the verifier compares against, so their hashes and
their loaded ``__file__`` paths are checked before any of their functions is used.
"""

import contextlib
import importlib
import sys
import typing as typ
from pathlib import Path

from verify_native_rate304_sequence_constants import (
    ACTIVE_USER_COUNT,
    BASE,
    CASES,
    CLOSURE_SIZE,
    DATA,
    DEADLINE,
    EXE,
    HELPER_PIN_COUNT,
    INODE,
    NS,
    PID,
    PLAN,
    ROM,
    RUNNER,
    SCRIPT_PIN_COUNT,
    SERVER_PORT,
    START,
)
from verify_native_rate304_sequence_support import need, pin, read, sha

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types
    from types import ModuleType

    from verify_native_rate304_sequence_support import Modules, Report


@contextlib.contextmanager
def frozen(raw: Path) -> cabc.Iterator[Modules]:
    """Import the frozen sources of ``raw`` and restore the import state afterwards.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.

    Yields
    ------
    tuple[types.ModuleType, ...]
        The rate304 control, the rate304 cases, the readiness, the capture and the
        TCP modules, in that order.
    """
    original_modules = sys.modules.copy()
    original_path = sys.path.copy()
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        freeze = read(raw / "source-freeze.json")
        root = raw / "sources"
        for filename, digest in freeze["hashes"].items():
            need(sha(root / filename) == digest, f"Frozen module differs: {filename}")
            sys.modules.pop(Path(filename).stem, None)
        sys.path.insert(0, str(root))
        yield (
            importlib.import_module("native_rate304_control"),
            importlib.import_module("native_rate304_cases"),
            importlib.import_module("native_control_readiness"),
            importlib.import_module("protocol_capture"),
            importlib.import_module("pcap_tcp"),
        )
    finally:
        for name in set(sys.modules) - original_modules.keys():
            del sys.modules[name]
        sys.modules.update(original_modules)
        sys.path[:] = original_path
        sys.dont_write_bytecode = original_bytecode


def _check_closure(
    raw: Path, prep: Path, freeze: Report, proposed: dict[str, str]
) -> None:
    """Check the approved source closure and the bytes of each approved source.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    prep : pathlib.Path
        The ``raw/preparation`` directory of the corpus.
    freeze : dict[str, typing.Any]
        The parsed ``source-freeze.json``.
    proposed : dict[str, str]
        The proposed source closure, from name to digest.
    """
    closure = pin(prep / "approved-source-closure.sha256")
    need(
        len(closure) == len(freeze["hashes"]) == len(proposed) == CLOSURE_SIZE
        and closure == {f"scripts/{name}": digest for name, digest in proposed.items()}
        and freeze["hashes"] == proposed,
        "Approved 35-module closure differs",
    )
    for name, digest in proposed.items():
        need(
            sha(raw / "sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Approved source byte differs: {name}",
        )


def _check_helpers(raw: Path, prep: Path, freeze: Report) -> None:
    """Check the three approved helper pins and the bytes of each helper.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    prep : pathlib.Path
        The ``raw/preparation`` directory of the corpus.
    freeze : dict[str, typing.Any]
        The parsed ``source-freeze.json``.
    """
    helpers = pin(prep / "approved-helpers.sha256")
    need(
        len(helpers) == HELPER_PIN_COUNT
        and freeze["helper_hashes"]
        == {Path(name).name: digest for name, digest in helpers.items()},
        "Three helper pins differ",
    )
    for name, digest in freeze["helper_hashes"].items():
        need(
            sha(raw / "helper-sources" / name) == digest
            and sha(prep / "proposed-sources" / name) == digest,
            f"Approved helper byte differs: {name}",
        )


def _check_rate304_sources(
    raw: Path, prep: Path, cases: ModuleType, control: ModuleType
) -> None:
    """Check the rate304 producer and runner pins and the loaded frozen modules.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    prep : pathlib.Path
        The ``raw/preparation`` directory of the corpus.
    cases : types.ModuleType
        The loaded frozen rate304 cases module.
    control : types.ModuleType
        The loaded frozen rate304 control module.
    """
    two = pin(prep / "approved-rate304-sources.sha256")
    need(
        two
        == {
            "scripts/native_rate304_cases.py": CASES,
            "scripts/native_rate304_control.py": RUNNER,
        }
        and sha(raw / "sources/native_rate304_cases.py") == CASES
        and sha(raw / "sources/native_rate304_control.py") == RUNNER,
        "Rate304 producer/runner pins differ",
    )
    need(
        sha(Path(typ.cast("str", cases.__file__))) == CASES
        and sha(Path(typ.cast("str", control.__file__))) == RUNNER,
        "Loaded frozen implementation differs",
    )


def _check_script_pins(prep: Path) -> None:
    """Check the prewritten script set and the bytes of each prewritten script.

    Parameters
    ----------
    prep : pathlib.Path
        The ``raw/preparation`` directory of the corpus.
    """
    script_pin = pin(prep / "script-SHA256SUMS")
    need(len(script_pin) == SCRIPT_PIN_COUNT, "Prewritten script set differs")
    for name, digest in script_pin.items():
        need(
            name.startswith("state/native-sessions/native-rate304-preparation-03/")
            and sha(prep / Path(name).name) == digest,
            "Prewritten script byte differs",
        )


def _check_plan(raw: Path, cases: types.ModuleType) -> Report:
    """Check the prepared plan and its source hashes against the frozen cases module.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw/epoch`` directory of the corpus.
    cases : types.ModuleType
        The loaded frozen rate304 cases module.

    Returns
    -------
    dict[str, typing.Any]
        The parsed prepared plan.
    """
    plan = read(raw / "rate304-plan/plan.json")
    need(
        sha(raw / "rate304-plan/plan.json") == PLAN
        and plan == cases.source_plan(plan["environment"], SERVER_PORT)
        and read(raw / "rate304-plan/source-hashes.json")["plan.json"] == PLAN,
        "Prepared plan/source differs",
    )
    return plan


def source_identity(corpus: Path, modules: Modules) -> Report:
    """Check the approved source identity of the frozen modules of ``corpus``.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    modules : tuple[types.ModuleType, ...]
        The frozen modules yielded by :func:`frozen`.

    Returns
    -------
    dict[str, typing.Any]
        The parsed prepared plan.
    """
    raw, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    control, cases, _, _, _ = modules
    freeze = read(raw / "source-freeze.json")
    proposed = read(prep / "proposed-source-closure.json")["hashes"]
    _check_closure(raw, prep, freeze, proposed)
    _check_helpers(raw, prep, freeze)
    _check_rate304_sources(raw, prep, cases, control)
    _check_script_pins(prep)
    return _check_plan(raw, cases)


def identity(corpus: Path) -> None:
    """Check the stopped preparation, the staged readiness and the runtime identity.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    raw, prep = corpus / "raw/epoch", corpus / "raw/preparation"
    prepared = read(prep / "preflight.json")
    runtime, receipt = read(raw / "runtime.json"), read(raw / "capture-ready.json")
    proof = read(raw / "actual-emulator-proof.json")
    need(
        prepared["status"] == "prepared_stopped"
        and prepared["prepared"]["working.dsk"]["inode"] == INODE
        and prepared["prepared"]["base.dsk"]["sha256"] == BASE
        and prepared["prepared"]["working.dsk"]["sha256"] == BASE
        and prepared["prepared"]["rom"]["sha256"] == ROM
        and all(
            prepared["source_before"][name] == prepared["source_after"][name]
            for name in ("base", "rom")
        )
        and prepared["catalog"]["banned_absent"]
        and len(prepared["catalog"]["active_users"]) == ACTIVE_USER_COUNT,
        "Stopped preparation identity differs",
    )
    for name, record in (
        ("disk", "disk-ready.json"),
        ("capture", "guest-capture-ready.json"),
        ("capture", "guest-capture-resume-ready.json"),
    ):
        item = read(raw / record)
        need(
            item["phase"] == name
            and item["pid"] == PID
            and item["start_ticks"] == int(START)
            and item["working_inode"] == INODE
            and item["netns_inode"] == NS
            and item["exe_sha256"] == EXE
            and item["deadline_utc"] == DEADLINE,
            "Staged readiness identity differs",
        )
    need(
        runtime["emulator_pid"] == receipt["emulator_pid"] == proof["pid"] == PID
        and runtime["emulator_starttime"]
        == receipt["emulator_starttime"]
        == proof["starttime"]
        == START
        and runtime["emulator_netns_inode"] == receipt["emulator_netns_inode"] == NS
        and runtime["owned_working_image_inode"]
        == receipt["owned_working_image_inode"]
        == proof["working_image_inode"]
        == INODE
        and runtime["emulator_sha256"] == receipt["emulator_sha256"] == EXE
        and runtime["native_data_sha256"] == receipt["native_data_sha256"] == DATA
        and runtime["full_file_baseline"]
        == receipt["full_file_baseline"]
        == "not_exercised"
        and receipt["deadline_utc"] == DEADLINE,
        "Runtime/receipt identity or fixed deadline differs",
    )
    need(
        (raw / "complete-asrun.exit").read_text().strip() == "1"
        and "git" in (raw / "complete-asrun.stderr").read_text()
        and "exit status 128" in (raw / "complete-asrun.stderr").read_text()
        and (raw / "resume-asrun.exit").read_text().strip() == "0"
        and (raw / "partial-runtime-builder-01/runtime.json").is_file()
        and (
            raw / "partial-runtime-builder-01/sources/native_rate304_control.py"
        ).is_file()
        and (raw / "readiness.exit").read_text().strip() == "0"
        and (raw / "case-launch-asrun.exit").read_text().strip() == "0"
        and (raw / "coordinator.exit").read_text().strip() == "1",
        "Retained procedural failure or case status differs",
    )
