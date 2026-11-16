"""Replay the frozen board sources and check the plan that they produced.

``frozen`` imports the retained source copy in place of the live modules and
restores the interpreter's state on exit. ``source_and_plan`` checks the plan, its
hashes and the stopped baseline that the frozen source wrote.
"""

import importlib
import json
import sys
import typing as typ
from contextlib import contextmanager

from verify_native_board_checks import Report, need, read, sha
from verify_native_board_pins import CASES, DATA, ENDPOINT_PORT, PLAN, RUNNER

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    from pathlib import Path
    from types import ModuleType


@contextmanager
def frozen(corpus: Path) -> cabc.Iterator[tuple[ModuleType, ...]]:
    """Import the frozen board sources, restoring the interpreter state on exit.

    Yields
    ------
    tuple[types.ModuleType, ...]
        The control, cases, readiness, capture and tcp modules of the frozen sources.
    """
    original_modules = sys.modules.copy()
    original_path = sys.path.copy()
    original_bytecode = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        root = corpus / "sources/protocol"
        closure = read(corpus / "sources/dependency-closure.json")
        need(
            closure["module_count"] == len(closure["hashes"]), "Source closure differs"
        )
        for name, digest in closure["hashes"].items():
            need(sha(root / f"{name}.py") == digest, f"Frozen source differs: {name}")
            sys.modules.pop(name, None)
        path = str(root)
        if path in sys.path:
            sys.path.remove(path)
        sys.path.insert(0, path)
        yield (
            importlib.import_module("native_board_control"),
            importlib.import_module("native_board_cases"),
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


def source_and_plan(corpus: Path, modules: tuple[ModuleType, ...]) -> Report:
    """Check the as-run sources, the generated plan and the stopped baseline.

    Returns
    -------
    dict[str, typing.Any]
        The generated board plan, once its identity is checked.
    """
    raw = corpus / "raw"
    control, cases, _, capture, _ = modules
    freeze = read(raw / "source-freeze.json")
    closure = read(corpus / "sources/dependency-closure.json")["hashes"]
    need(
        freeze["hashes"]["native_board_cases.py"] == CASES
        and freeze["hashes"]["native_board_control.py"] == RUNNER
        and set(freeze["hashes"]).issubset({f"{name}.py" for name in closure}),
        "As-run board source identity differs",
    )
    for name, digest in freeze["hashes"].items():
        need(
            sha(raw / "sources" / name) == digest
            and sha(corpus / "sources/protocol" / name) == digest,
            f"As-run source differs: {name}",
        )
    need(
        sha(corpus / "sources/helpers/native_capture_receipt.py")
        == (corpus / "preparation/approved-helper.sha256").read_text().split()[0]
        and sha(corpus / "sources/protocol/native_board_control.py") == RUNNER
        and sha(corpus / "sources/protocol/native_board_cases.py") == CASES,
        "Approved receipt helper or B80 source differs",
    )
    plan = read(raw / "board-plan/plan.json")
    need(
        sha(raw / "board-plan/plan.json") == PLAN
        and read(raw / "board-plan/source-hashes.json")
        == {
            "plan.json": PLAN,
            "native_board_cases.py": CASES,
            "native_board_control.py": RUNNER,
        }
        and plan == cases.source_plan(plan["environment"], ENDPOINT_PORT)
        and plan["oracle_sha256"] == capture.ORACLE_SHA256 == DATA,
        "Generated board plan, endpoint or oracle differs",
    )
    need(
        read(raw / "runtime.json")["stopped_board_baseline"]
        == {
            "path": "Hotline19/MessageBoard.txt",
            "catalog_id": 11191,
            "data_size": 0,
            "resource_size": 0,
            "finder_type": "TEXT",
            "finder_creator": "ttxt",
        },
        "Empty stopped board baseline differs",
    )
    need(
        control.sha((json.dumps(plan, indent=2) + "\n").encode()) == PLAN,
        "Plan encoding differs",
    )
    return plan
