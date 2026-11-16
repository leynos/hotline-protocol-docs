"""Write a capture directory and check one for ``protocol_capture``.

Part of the capture driver's module set (``protocol_capture.CAPTURE_MODULES``).
A capture directory holds the plan as read, the report and a checksum list. This
module builds the report, writes the three files and checks a directory that
holds them; ``protocol_capture`` re-exports :func:`digest` and calls the rest.
"""

import dataclasses as dc
import datetime as dt
import hashlib
import json
import typing as typ

from protocol_capture_decode import HEADER_SIZE, decode_frame
from protocol_capture_recorder import RecorderBase, streams_of

if typ.TYPE_CHECKING:
    from pathlib import Path

FILES = ("plan.json", "report.json")
SIZE_START = 16
IDENTITY_SCOPE = (
    "Local binary hash verified; remote process identity is operator-reported"
)

type Json = dict[str, typ.Any]


def digest(data: bytes) -> str:
    """Return a SHA-256 identity for exact retained bytes.

    Returns
    -------
    str
        The hash in lower-case hexadecimal.
    """
    return hashlib.sha256(data).hexdigest()


@dc.dataclass(frozen=True, slots=True)
class Outcome:
    """What a run of a plan left.

    Attributes
    ----------
    plan : dict[str, typing.Any]
        The validated plan.
    source : bytes
        The plan file's bytes.
    recorder : RecorderBase
        The recorder that ran the steps.
    status : str
        ``"completed"`` or ``"failed"``.
    error : str
        The failure, or the empty string.
    completed : int
        The number of steps that finished.
    """

    plan: Json
    source: bytes
    recorder: RecorderBase
    status: str
    error: str
    completed: int


def build_report(run: Outcome, identity: Json) -> Json:
    """Describe a run.

    Parameters
    ----------
    run : Outcome
        The finished run.
    identity : dict[str, typing.Any]
        The record of the scripts that made it, from ``capture_identity``. Its
        digest is ``driver_sha256`` and the whole record is ``driver_identity``.

    Returns
    -------
    dict[str, typing.Any]
        The report, in the order of its keys as written.
    """
    recorder = run.recorder
    return {
        "schema_version": 1,
        "profile": run.plan["profile"],
        "status": run.status,
        "native_conformance": False,
        "identity_scope": IDENTITY_SCOPE,
        "operator": run.plan["operator"],
        "oracle_sha256": run.plan["oracle_sha256"],
        "plan_sha256": digest(run.source),
        "driver_sha256": identity["digest"],
        "driver_identity": identity,
        "recorded_at_utc": dt.datetime.now(dt.UTC).isoformat(),
        "started_at_utc": recorder.started_at_utc,
        "gap_ids": run.plan["gap_ids"],
        "completed_actions": run.completed,
        "error": run.error,
        "events": recorder.events,
        "frames": recorder.frames,
        "streams": recorder.streams(),
    }


def write_directory(output: Path, source: bytes, report: Json) -> None:
    """Write the plan, the report and the checksum list.

    Parameters
    ----------
    output : pathlib.Path
        The directory, which exists.
    source : bytes
        The plan file's bytes, kept as read.
    report : dict[str, typing.Any]
        The report.
    """
    (output / "plan.json").write_bytes(source)
    (output / "report.json").write_text(
        json.dumps(report, indent=2) + "\n", encoding="utf-8"
    )
    (output / "checksums.sha256").write_text(
        "".join(f"{digest((output / name).read_bytes())}  {name}\n" for name in FILES),
        encoding="utf-8",
    )


def check_inventory(directory: Path) -> None:
    """Check the checksum list and the files it names.

    Raises
    ------
    ValueError
        If a line names another file or repeats one, a hash differs, or a file
        is missing from the list.
    """
    names: set[str] = set()
    listing = (directory / "checksums.sha256").read_text(encoding="utf-8")
    for line in listing.splitlines():
        expected, name = line.split("  ", 1)
        if name not in FILES or name in names:
            message = "Invalid checksum inventory"
            raise ValueError(message)
        names.add(name)
        if digest((directory / name).read_bytes()) != expected:
            message = f"Checksum mismatch: {name}"
            raise ValueError(message)
    if names != set(FILES):
        message = "Incomplete checksum inventory"
        raise ValueError(message)


def _incomplete(report: Json, plan: Json) -> bool:
    """Say whether a report has an error or fewer steps than its plan.

    Returns
    -------
    bool
        ``True`` if it records an error or a different number of steps.
    """
    return bool(report["error"]) or report["completed_actions"] != len(plan["steps"])


def check_report(report: Json, plan: Json, plan_bytes: bytes) -> None:
    """Check a report against its plan, up to the byte streams.

    Raises
    ------
    ValueError
        For the first of: another profile or a native claim, another plan or
        oracle hash, an unknown status, a completed report that is not
        complete, and streams that the events do not rebuild.
    """
    if report["profile"] != plan["profile"] or report["native_conformance"]:
        message = "Evidence profile mismatch"
        raise ValueError(message)
    if (
        report["plan_sha256"] != digest(plan_bytes)
        or report["oracle_sha256"] != plan["oracle_sha256"]
    ):
        message = "Source identity mismatch"
        raise ValueError(message)
    if report["status"] not in {"completed", "failed"}:
        message = "Unknown capture status"
        raise ValueError(message)
    if report["status"] == "completed" and _incomplete(report, plan):
        message = "Incomplete plan reported as completed"
        raise ValueError(message)
    if streams_of(report["events"]) != report["streams"]:
        message = "Stream reconstruction mismatch"
        raise ValueError(message)


def _split_frames(data: bytes, index: int, name: str) -> tuple[list[Json], bytes]:
    """Cut complete frames off the front of received bytes.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], bytes]
        The decoded frames and the bytes left over.
    """
    frames: list[Json] = []
    while len(data) >= HEADER_SIZE:
        size = HEADER_SIZE + int.from_bytes(data[SIZE_START:HEADER_SIZE], "big")
        if size > len(data):
            break
        frames.append({
            "action": index,
            "connection": name,
            **decode_frame(data[:size]),
        })
        data = data[size:]
    return frames, data


def _check_completed_read(step: Json, matched: list[Json], left: bytes) -> None:
    """Check a frame read of a completed capture.

    Raises
    ------
    ValueError
        If bytes are left over or no frame was read, or the last frame is not
        the one the step matches.
    """
    if left or not matched:
        message = "Completed frame read has incomplete bytes"
        raise ValueError(message)
    if not all(matched[-1][k] == v for k, v in step.get("match_frame", {}).items()):
        message = "Completed frame read did not match"
        raise ValueError(message)


def check_frames(plan: Json, report: Json) -> None:
    """Rebuild the decoded frames from the events and compare them.

    Raises
    ------
    ValueError
        If a completed frame read is incomplete or did not match, or the report's
        frames are not the rebuilt ones.
    """
    frames: list[Json] = []
    for index, step in enumerate(plan["steps"]):
        if step["op"] != "read_frame":
            continue
        data = bytes.fromhex(
            "".join(
                e["hex"]
                for e in report["events"]
                if e["action"] == index
                and e["event"] == "receive"
                and e["connection"] == step["connection"]
            )
        )
        found, left = _split_frames(data, index, step["connection"])
        frames.extend(found)
        if report["status"] == "completed":
            _check_completed_read(step, found, left)
    if report["frames"] != frames:
        message = "Decoded frame mismatch"
        raise ValueError(message)
