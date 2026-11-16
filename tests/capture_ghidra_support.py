"""Shared set-up for the characterization tests of ``capture-ghidra-evidence.py``.

The script is loaded with the fake ``mcp`` library of ``ghidra_bridge_fake`` in
place, and the replies come from the retained query records, so the tests need
neither Ghidra nor a bridge.
"""

import asyncio
import collections.abc as cabc
import json
import types
import typing as typ

from ghidra_bridge_fake import Bridge, ok, retained_record
from script_loading import load_script

if typ.TYPE_CHECKING:
    from pathlib import Path

    import pytest

FIRST = retained_record("A-10005710")
IDENTITY = FIRST["program"]
SERVER = FIRST["mcp_server"]

type Harness = cabc.Callable[
    [list[dict[str, typ.Any]]], tuple[types.ModuleType, Bridge]
]


def make_harness(monkeypatch: pytest.MonkeyPatch, script: Path) -> Harness:
    """Build a loader that installs a scripted bridge and loads the script.

    Parameters
    ----------
    monkeypatch : pytest.MonkeyPatch
        The fixture that restores ``sys.modules`` afterwards.
    script : pathlib.Path
        The script under test.

    Returns
    -------
    collections.abc.Callable
        A function from the replies to the loaded module and its bridge.
    """

    def make(replies: list[dict[str, typ.Any]]) -> tuple[types.ModuleType, Bridge]:
        """Install the bridge and load the script.

        Returns
        -------
        tuple[types.ModuleType, Bridge]
            The loaded script and the bridge that it will talk to.
        """
        bridge = Bridge(replies, SERVER)
        bridge.install(monkeypatch)
        return load_script(script, "capture_ghidra_under_test"), bridge

    return make


def write_plan(tmp_path: Path, queries: list[dict[str, typ.Any]]) -> Path:
    """Write a plan file.

    Returns
    -------
    pathlib.Path
        The plan's path.
    """
    path = tmp_path / "plan.json"
    path.write_text(json.dumps(queries), encoding="utf-8")
    return path


def identity() -> dict[str, typ.Any]:
    """Build a successful program-identity reply.

    Returns
    -------
    dict[str, typing.Any]
        The reply.
    """
    return ok(dict(IDENTITY))


def run(module: types.ModuleType, plan: Path, output: Path) -> None:
    """Run the script's ``capture`` coroutine to completion."""
    asyncio.run(module.capture(plan, output))


def sequence(*queries: dict[str, typ.Any]) -> list[dict[str, typ.Any]]:
    """Build the replies for plain queries: identity, one success each, identity.

    Returns
    -------
    list[dict[str, typing.Any]]
        The replies.
    """
    return [identity(), *(ok({"name": q["id"]}) for q in queries), identity()]
