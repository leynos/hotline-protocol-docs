"""Describe the subjects of the missing-alias planner's order test.

A subject is the runtime record that the planner reads, as parsed JSON, and a
function that runs the planner's checks on a possibly faulted copy of it. The test
replays recorded faults against these subjects; the recording tool builds the same
subjects while the pristine scripts are on ``sys.path``.
"""

import hashlib
import typing as typ

import native_missing_alias_cases as cases

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type State = dict[str, typ.Any]
type Subject = tuple[State, cabc.Callable[[State], object]]

FINDER_INFO = b"U54TM54X" + bytes(24)  # the pre-staged Finder info of the target
CONTROL_PORT = 16020  # the isolated control port that the planner insists on
ENVIRONMENT = {
    "fixture_profile": "control-only",
    "emulator_pid": 123,
    "emulator_starttime": 456,
    "emulator_sha256": "a" * 64,
    "emulator_netns_inode": 789,
    "owned_working_image": "/owned/native-alias-live-05/working.dsk",
    "owned_working_image_inode": 321,
    "owned_runtime": "/owned/native-alias-live-05",
    "initial_finf_sha256": hashlib.sha256(FINDER_INFO).hexdigest(),
}
WINDOW = {
    "capture_window_profile": "native-missing-alias-ui-30m-v1",
    "capture_window_purpose": "native-missing-alias-positive",
}


def planner_subject(environment: dict[str, typ.Any]) -> Subject:
    """Build the subject of the planner's checks on one runtime record.

    Returns
    -------
    tuple[dict, collections.abc.Callable]
        The record and the port, and a function that runs ``source_plan`` on them.
    """
    state: State = {"environment": environment, "port": CONTROL_PORT}

    def call(changed: State) -> object:
        """Run the planner on the changed record.

        Returns
        -------
        object
            The plan.
        """
        return cases.source_plan(changed["environment"], changed["port"])

    return state, call


def subjects() -> dict[str, Subject]:
    """Build every subject, by name.

    Returns
    -------
    dict[str, tuple[dict, collections.abc.Callable]]
        The record and the check of each subject.
    """
    return {
        "planner-default": planner_subject(dict(ENVIRONMENT)),
        "planner-window": planner_subject({**ENVIRONMENT, **WINDOW}),
    }
