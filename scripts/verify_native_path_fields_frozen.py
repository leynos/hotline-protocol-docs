"""Import the frozen corpus sources in isolation, and restore the interpreter after."""

import importlib
import sys
import typing as typ
from contextlib import contextmanager
from pathlib import Path

from verify_native_path_fields_core import need, read, sha

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

# The frozen modules that the verifier replays, in the order it imports them.
FROZEN_MODULES = (
    "native_path_fields_control",
    "native_path_fields_cases",
    "native_control_readiness",
    "protocol_capture",
    "pcap_tcp",
)


def _unload_checked(root: Path, hashes: dict[str, str]) -> None:
    """Check each frozen source's digest, and forget any module of the same name."""
    for name, digest in hashes.items():
        need(sha(root / name) == digest, f"Frozen source differs: {name}")
        sys.modules.pop(Path(name).stem, None)


def _import_frozen() -> tuple[types.ModuleType, ...]:
    """Import the frozen modules from the front of the path.

    Returns
    -------
    tuple[types.ModuleType, ...]
        The imported modules, in the order of FROZEN_MODULES.
    """
    return tuple(importlib.import_module(name) for name in FROZEN_MODULES)


def _check_loaded(
    modules: tuple[types.ModuleType, ...], hashes: dict[str, str]
) -> None:
    """Check that each loaded module was read from a file with its pinned digest."""
    for module in modules:
        need(isinstance(module.__file__, str), "Frozen module lacks source path")
        source_path = typ.cast("str", module.__file__)
        name = Path(source_path).name
        need(sha(Path(source_path)) == hashes[name], "Loaded source differs")


@contextmanager
def frozen(raw: Path) -> cabc.Iterator[tuple[types.ModuleType, ...]]:
    """Import the frozen modules, yield them, then restore the interpreter state.

    Yields
    ------
    tuple[types.ModuleType, ...]
        The frozen modules, in the order of FROZEN_MODULES.
    """
    before_modules = sys.modules.copy()
    before_path = sys.path.copy()
    before_bytecode = sys.dont_write_bytecode
    freeze = read(raw / "source-freeze.json")
    root = raw / "sources"
    try:
        sys.dont_write_bytecode = True
        _unload_checked(root, freeze["hashes"])
        sys.path.insert(0, str(root))
        modules = _import_frozen()
        _check_loaded(modules, freeze["hashes"])
        yield modules
    finally:
        for name in set(sys.modules) - before_modules.keys():
            del sys.modules[name]
        sys.modules.update(before_modules)
        sys.path[:] = before_path
        sys.dont_write_bytecode = before_bytecode
