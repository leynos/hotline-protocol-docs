"""Route the handshake verifier's capture and packet readers to synthetic ones.

The verifier may hold a reader in more than one module, so a replacement is
made in every module that has the name. That keeps the order tests valid both
for the verifier as one module and for the verifier split over several.
"""

import importlib
import importlib.util
import typing as typ

import verify_native_handshakes as handshakes

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

    import pytest


def readers() -> list[types.ModuleType]:
    """List the modules that hold the capture and packet readers.

    Returns
    -------
    list[types.ModuleType]
        The verifier module, and the timing module when the split has been made.
    """
    modules = [handshakes]
    if importlib.util.find_spec("verify_native_handshake_timing") is not None:
        modules.append(importlib.import_module("verify_native_handshake_timing"))
    return modules


def patch_all(
    monkeypatch: pytest.MonkeyPatch, **replacements: cabc.Callable[..., typ.Any]
) -> None:
    """Replace a reader in every module that holds it."""
    for module in readers():
        for name, value in replacements.items():
            if hasattr(module, name):
                monkeypatch.setattr(module, name, value)
