"""Describe the subjects of the native planners' refusal-order test.

A subject is the runtime record that a planner reads, with its port, as parsed
JSON, and a function that runs the planner's checks on a possibly faulted copy of
them. The test replays recorded faults against these subjects; the recording tool
builds the same subjects while the pristine scripts are on ``sys.path``.
"""

import importlib
import json
import tempfile
import typing as typ
from pathlib import Path

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]

EVIDENCE = Path(__file__).resolve().parents[1] / "evidence/gap-remediation/2026-11-14"
# subject name -> (planner module, retained runtime record, the planner's port)
SPECS = {
    "liveness": (
        "native_liveness_cases",
        "native-liveness-01/raw/runtime.json",
        15840,
    ),
    "path-fields": (
        "native_path_fields_cases",
        "native-path-fields-01/raw/epoch/runtime.json",
        15900,
    ),
    "roster-overlap": (
        "native_roster_overlap_cases",
        "native-roster-overlap-01/raw/runtime-asrun.json",
        15820,
    ),
    "rate304-sequence": (
        "native_rate304_cases",
        "native-rate304-sequence-01/raw/epoch/runtime.json",
        15880,
    ),
    "rate304-first-pair": (
        "native_rate304_cases",
        "native-rate304-first-pair-01/raw/runtime.json",
        15880,
    ),
    "ban-expiry": (
        "native_ban_expiry_cases",
        "native-ban-expiry-first-01/raw/runtime-asrun.json",
        15800,
    ),
    "configured-ban": (
        "native_configured_ban_cases",
        "native-configured-ban-01/native-configured-apply-c66/runtime-asrun.json",
        15770,
    ),
}


def plan_call(module: str, changed: State) -> object:
    """Run the planner of ``module`` on a changed record and port.

    Returns
    -------
    object
        The plan, or for the planners that write a directory of plans, the digests
        of the files written.
    """
    cases = importlib.import_module(module)
    environment, port = changed["environment"], changed["port"]
    if hasattr(cases, "source_plan"):
        return cases.source_plan(environment, port)
    with tempfile.TemporaryDirectory() as temporary:
        if module == "native_ban_expiry_cases":
            return cases.plan("kick", [], environment, port)
        return cases.write_plans(Path(temporary) / "plans", environment, port)


def planner_subject(name: str) -> Subject:
    """Build the subject of one planner.

    Parameters
    ----------
    name : str
        A key of ``SPECS``.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The runtime record and port, and a function that runs the planner on them.
    """
    module, record, port = SPECS[name]
    environment = json.loads((EVIDENCE / record).read_text())
    state: State = {"environment": environment, "port": port}
    return state, lambda changed: plan_call(module, changed)
