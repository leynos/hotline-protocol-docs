"""Describe the subjects of the order tests of the 121 and transition drivers.

Each subject is the parsed JSON of a retained capture's report and plan, and a
function that replays the driver's semantic gates on a copy of them with faults
put in. The two drivers are the capture scripts ``verify_native_121_default`` and
``verify_native_settings_transition``; the captures are those that their own
evidence verifiers replay.
"""

import importlib
import json
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc
    import types

type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]

ROOT = Path(__file__).resolve().parents[1]
GAP = ROOT / "evidence/gap-remediation"
DEFAULTS = GAP / "2026-11-14/native-121-defaults-01/observe"
TRANSITIONS = GAP / "2026-11-13/native-settings-transitions-01/observe"


def load(directory: Path) -> State:
    """Read a capture's report and plan.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``report.json`` and ``plan.json``.
    """
    return {
        "report": json.loads((directory / "report.json").read_text(encoding="utf-8")),
        "plan": json.loads((directory / "plan.json").read_text(encoding="utf-8")),
    }


def driver(name: str) -> types.ModuleType:
    """Import a driver by name, from whichever ``scripts`` is first on the path.

    Returns
    -------
    types.ModuleType
        The module.
    """
    return importlib.import_module(name)


def subjects() -> dict[str, Subject]:
    """Build the subjects, each with the retained capture's report and plan.

    Returns
    -------
    dict[str, tuple[dict[str, typing.Any], collections.abc.Callable]]
        The subject by name.
    """
    defaults = driver("verify_native_121_default")
    transition = driver("verify_native_settings_transition")
    return {
        "default-semantic": (
            load(DEFAULTS),
            lambda s: defaults.semantic(s["report"], s["plan"]),
        ),
        "transition-semantic": (
            load(TRANSITIONS),
            lambda s: transition.semantic(s["report"], s["plan"]),
        ),
        "transition-partial": (
            load(TRANSITIONS),
            lambda s: transition.semantic(s["report"], s["plan"], completed_only=False),
        ),
    }
