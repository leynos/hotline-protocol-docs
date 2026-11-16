"""Share the constants and readers of the settings persistence corpus checks."""

import importlib.util
import json
import sys
import typing as typ

if typ.TYPE_CHECKING:
    import types
    from pathlib import Path

type Json = dict[str, typ.Any]

A46_CASES_SHA = "ecd3bba43abcefc31ad5f0aecd2c27f3d5c127e2d3ca7292e95cf05b4d344fe7"
A46_RUNNER_SHA = "9122c142d515811b9485c3fe728618152271a5adb85e547f0c3022e549d23c92"
A48_CASES_SHA = "29ad770ab95dd9035b46dd3a1616448efd8a987520f59567320db2a92c200229"
A48_RUNNER_SHA = "a2474c41ef7098f8fd00535712cb6e139497bdce269c176d0013865fa3cba23a"
A46_SOURCES = {
    "native_settings_persistence_cases.py": A46_CASES_SHA,
    "native_settings_persistence.py": A46_RUNNER_SHA,
}
A48_SOURCES = {
    "native_settings_persistence_cases.py": A48_CASES_SHA,
    "native_settings_persistence.py": A48_RUNNER_SHA,
}
FORKS = {
    11193: (
        "/Hotline19/Users/admin/UserData",
        734,
        "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    ),
    11201: (
        "/Hotline19/Users/fixture-low/UserData",
        734,
        "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    ),
    11202: (
        "/Hotline19/Prefs",
        175,
        "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    ),
}
PHASES = (1, 2)  # the A46 legacy phase and the A48 planned-EOF phase
SYN_FLAG = 2  # TCP flag bits that mark a connection's first packet
ACK_FLAG = 16
LAB_PORT = 15760  # the owned lab port that the plans connect to
GUEST_PORT = 5500  # the port that the guest forwards it to
PCAP_HEADER_BYTES = 24  # a capture with no packet is its 24-byte global header


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the check shape of every verifier
    message: str,
) -> None:
    """Keep checks active even when Python runs with optimization enabled.

    Raises
    ------
    ValueError
        With ``message``, when ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def read_json(path: Path) -> Json:
    """Parse a JSON file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


def load_frozen(name: str, path: Path) -> types.ModuleType:
    """Load a source file of the corpus as a module, leaving no bytecode behind.

    Parameters
    ----------
    name : str
        The name to give the module.
    path : pathlib.Path
        The retained source file.

    Returns
    -------
    types.ModuleType
        The executed module.

    Raises
    ------
    ValueError
        If the file cannot be loaded.
    """
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:
        message = "Frozen source loader missing"
        raise ValueError(message)
    module = importlib.util.module_from_spec(spec)
    previous = sys.dont_write_bytecode
    try:
        sys.dont_write_bytecode = True
        spec.loader.exec_module(module)
    finally:
        sys.dont_write_bytecode = previous
    return module
