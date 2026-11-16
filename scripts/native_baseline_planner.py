"""Share the identity check and the command line of the baseline-framed planners.

The settings-transition and 121-default planners each prepare one observation
between two copies of the pinned A7 baseline plan, accept a runtime record only
if it is the baseline's, and write the three plans to a new directory.
"""

import json
import typing as typ
from pathlib import Path

from native_pm_cases import load_baseline
from script_cli import UsageError

if typ.TYPE_CHECKING:
    import collections.abc as cabc

type Json = dict[str, typ.Any]
type Prepare = cabc.Callable[[Json, bytes], dict[str, Json]]

IDENTITY_KEYS = ("oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap")
OBSERVE = "observe"  # the label whose plan is written as indented JSON


def identified_baseline(runtime: Json, baseline_raw: bytes) -> Json:
    """Load the baseline and require that the runtime record is its own.

    Parameters
    ----------
    runtime : dict[str, typing.Any]
        The runtime record of the emulator.
    baseline_raw : bytes
        The baseline plan's bytes.

    Returns
    -------
    dict[str, typing.Any]
        The parsed baseline plan.

    Raises
    ------
    ValueError
        If the baseline fails :func:`native_pm_cases.load_baseline`, or the
        runtime record differs from the baseline's in an identity field.
    """
    baseline = load_baseline(baseline_raw)
    for key in IDENTITY_KEYS:
        if runtime.get(key) != baseline["environment"].get(key):
            message = "Runtime identity differs from pinned A7 baseline"
            raise ValueError(message)
    return baseline


def write_prepared(
    prepare: Prepare, *, runtime_record: str, baseline_plan: str, output: str
) -> None:
    """Prepare the three plans and write them to a new directory.

    The directory is created only after the plans are prepared, so a refused
    record leaves nothing behind. The baseline is written byte for byte for the
    preflight and the postflight; the observation is written as indented JSON.

    Parameters
    ----------
    prepare : collections.abc.Callable[[dict[str, typing.Any], bytes], dict]
        The planner's ``plans`` function.
    runtime_record : str
        The JSON record of the running emulator.
    baseline_plan : str
        The A7 baseline plan.
    output : str
        The directory to create; it must not exist.

    Raises
    ------
    UsageError
        If the output directory exists.
    """
    target = Path(output)
    if target.exists():
        message = "Refusing existing output"
        raise UsageError(message)
    baseline_raw = Path(baseline_plan).read_bytes()
    prepared = prepare(
        json.loads(Path(runtime_record).read_text(encoding="utf-8")), baseline_raw
    )
    target.mkdir(parents=True)
    for label, plan in prepared.items():
        (target / f"{label}.json").write_bytes(
            baseline_raw
            if label != OBSERVE
            else (json.dumps(plan, indent=2) + "\n").encode()
        )
