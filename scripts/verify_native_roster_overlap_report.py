"""Check the readiness captures, the native overlap result and the parent receipt."""

import typing as typ

from native_wire_names import FIELD_USER_ID, TYPE_PRESENCE_UPDATE
from verify_native_roster_overlap_common import (
    DEADLINE,
    NO_TEXT,
    ORACLE,
    PID,
    need,
    read,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

# The completed actions of each generic capture, the readiness and the postflight.
CAPTURE_ACTIONS = 18
# The completed actions and the retained frames of the native overlap case.
OVERLAP_ACTIONS = 35
OVERLAP_FRAMES = 16
# The frames and the events of the parent case acceptance receipt.
PARENT_FRAMES = 16
PARENT_EVENTS = 51
# The identifier of the stable-drain frame that the expected row is read from.
STABLE_DRAIN_ID = 13
# The identifier of the direct 304 acknowledgement that was never observed.
UNOBSERVED_ACK_ID = 20


def _check_preflight(raw: Path) -> None:
    """Check the parent preflight: the replay path correction and the deadline.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    preflight = read(raw / "parent-preflight.json")
    need(
        preflight["status"] == "parent_runtime_source_and18_readiness_pass"
        and preflight["initial_parent_replay_path_error"].startswith(
            "parent first used nonexistent captures/readiness"
        )
        and preflight["overlap_socket_actions"] == 0
        and preflight["pid"] == PID
        and preflight["deadline_utc"] == DEADLINE,
        "Parent readiness path correction differs",
    )


def _check_generic(
    raw: Path, label: str, capture: ModuleType, readiness: ModuleType
) -> None:
    """Check one generic capture and its source readiness plan.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    label : str
        The capture folder: ``readiness`` or ``postflight``.
    capture : types.ModuleType
        The frozen generic capture module.
    readiness : types.ModuleType
        The frozen readiness module.
    """
    folder = raw / label
    report = capture.verify_capture(folder)
    need(
        report["status"] == "completed"
        and report["completed_actions"] == CAPTURE_ACTIONS,
        f"{label} generic capture differs",
    )
    readiness.readiness(report)
    need(
        sha(folder / "plan.json") == sha(raw / "control-plans/readiness.json"),
        f"{label} source readiness plan differs",
    )


def _check_outcome(result: dict[str, typ.Any]) -> None:
    """Check the status, the snapshot, the action count and the frame count.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The parsed ``results/report.json``.
    """
    need(
        result["status"] == result["overlap_status"] == "completed"
        and result["teardown_status"] == "completed"
        and result["old_or_new_snapshot"] == "old"
        and result["error"] == NO_TEXT
        and result["late_observations"] == []
        and result["unparsed_hex"] == {"a": "", "b": ""}
        and result["completed_actions"] == OVERLAP_ACTIONS
        and len(result["frames"]) == OVERLAP_FRAMES,
        "Native overlap outcome differs",
    )


def _check_result_identity(raw: Path, result: dict[str, typ.Any]) -> None:
    """Check that the result names its plan, its receipt and the oracle.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    result : dict[str, typing.Any]
        The parsed ``results/report.json``.
    """
    need(
        result["plan_sha256"] == sha(raw / "results/plan.json")
        and result["receipt_sha256"] == sha(raw / "capture-ready.json")
        and result["oracle_sha256"] == ORACLE,
        "As-run result identity differs",
    )


def _setup_uids(
    result: dict[str, typ.Any], entries: dict[str, typ.Any], control: ModuleType
) -> tuple[int, int]:
    """Read the two user identifiers from the setup frames.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The parsed ``results/report.json``.
    entries : dict[str, typing.Any]
        The operation map entries, keyed by label.
    control : types.ModuleType
        The frozen control module.

    Returns
    -------
    tuple[int, int]
        The user identifiers of connections ``a`` and ``b``.
    """
    setup = result["frames"][: entries["setup"]["frame_range"][1]]
    recorder = type("FrozenSetup", (), {"frames": setup, "variables": {}})()
    b_update = next(
        f for f in setup if f["connection"] == "a" and f["type"] == TYPE_PRESENCE_UPDATE
    )
    from verify_native_shx import fields

    recorder.variables["b_uid"] = fields(b_update)[FIELD_USER_ID]
    return control.check_setup(recorder)


def _check_drain(result: dict[str, typ.Any], control: ModuleType) -> None:
    """Check the old overlap snapshot, the stable drain row and the absent ACK.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The parsed ``results/report.json``.
    control : types.ModuleType
        The frozen control module.
    """
    entries = {entry["label"]: entry for entry in result["operation_map"]}
    a_uid, b_uid = _setup_uids(result, entries, control)
    start, end = entries["overlap-drain"]["frame_range"]
    need(
        control.check_overlap(result["frames"][start:end], a_uid, b_uid) == "old",
        "Old overlap snapshot or five required frames differ",
    )
    stable = entries["stable-drain"]["frame_range"]
    control.exact_rows(
        control.one(result["frames"][slice(*stable)], "a", 0, STABLE_DRAIN_ID, 1),
        a_uid,
        b_uid,
        b_new=True,
    )
    need(
        not any(
            f["is_reply"] and f["id"] == UNOBSERVED_ACK_ID for f in result["frames"]
        ),
        "Unobserved direct 304 ACK was invented",
    )


def _check_decoded(result: dict[str, typ.Any], capture: ModuleType) -> None:
    """Check that each drain frame decodes to the fields that were retained.

    Parameters
    ----------
    result : dict[str, typing.Any]
        The parsed ``results/report.json``.
    capture : types.ModuleType
        The frozen generic capture module, which decodes the raw bytes.
    """
    for f in result["frames"]:
        if f.get("raw_hex"):
            decoded = capture.decode_frame(bytes.fromhex(f["raw_hex"]))
            need(
                all(
                    decoded[key] == f[key]
                    for key in ("flags", "is_reply", "type", "id", "error", "fields")
                ),
                "Decoded drain frame differs from retained raw bytes",
            )


def _check_parent(raw: Path) -> None:
    """Check the parent case acceptance receipt.

    Parameters
    ----------
    raw : pathlib.Path
        The ``raw`` directory of the corpus.
    """
    parent = read(raw / "parent-case-acceptance.json")
    need(
        parent["asrun_plan_equal"] is True
        and parent["status"].startswith(
            "parent_custom_schedule_and_completed_outcome_accepted"
        )
        and parent["packet_pairing_pending"] is True
        and parent["frames"] == PARENT_FRAMES
        and parent["events"] == PARENT_EVENTS,
        "Parent overlap receipt differs",
    )


def report_gate(corpus: Path, modules: tuple[ModuleType, ...]) -> dict[str, typ.Any]:
    """Check the readiness captures, the native overlap result and its drain.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    modules : tuple[types.ModuleType, ...]
        The frozen modules from :func:`verify_native_roster_overlap_common.frozen`.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``results/report.json``.
    """
    raw = corpus / "raw"
    control, _, readiness, capture, _ = modules
    _check_preflight(raw)
    for label in ("readiness", "postflight"):
        _check_generic(raw, label, capture, readiness)
    result = read(raw / "results/report.json")
    plan = read(raw / "results/plan.json")
    need(plan == control.prepared(raw / "roster-plan"), "As-run roster plan differs")
    _check_outcome(result)
    _check_result_identity(raw, result)
    control.verify_operation_map(plan, result)
    _check_drain(result, control)
    _check_decoded(result, capture)
    _check_parent(raw)
    return result
