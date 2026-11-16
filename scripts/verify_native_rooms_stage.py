"""Check one retained room report: its plan, its bytes, its meaning and its tails."""

import dataclasses as dc
import json
import typing as typ

import native_room_cases as cases
from native_packet_evidence import reconcile
from native_wire_names import FRAME_HEADER_BYTES
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_auth import selected
from verify_native_core import require
from verify_native_live_accounts import waits
from verify_native_rooms_reports import identities
from verify_native_rooms_semantic import semantic
from verify_native_rooms_tail import validate_tail
from verify_native_rooms_wire import ACKLESS_REQUESTS
from verify_native_shx import sha

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

FAILED_REPORTS = {
    "basics-width-failure": ("EOFError:", 37),
    "refusals-ack-timeout": ("TimeoutError:", 34),
}
ROOM_SCENARIOS = (
    "basics",
    "topics",
    "lifecycle",
    "concurrent",
    "create_invites",
    "invites",
    "refusals",
    "formatting",
)


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The files of one room corpus, read once before its reports are checked.

    Attributes
    ----------
    directory : Path
        The corpus directory.
    manifest : dict
        The parsed manifest.
    expected : dict
        The planned steps and expectation of each completed suite.
    runtime : dict
        The parsed runtime record.
    tails : dict
        The retained unread tails of each report, per view.
    host : Packets
        The packets of the host recording.
    guest : Packets
        The packets of the guest recording.
    """

    directory: Path
    manifest: dict[str, typ.Any]
    expected: dict[str, tuple[list[dict[str, typ.Any]], dict[str, typ.Any]]]
    runtime: dict[str, typ.Any]
    tails: dict[str, typ.Any]
    host: Packets
    guest: Packets


def check_stage(corpus: Corpus, name: str) -> tuple[Report, Report]:
    """Check one retained report and return it with its packet observation.

    Parameters
    ----------
    corpus : Corpus
        The files of the corpus.
    name : str
        The name of the report, which is also its directory.

    Returns
    -------
    tuple[Report, Report]
        The verified report and the reconciled packet observation.
    """
    case = corpus.directory / name
    plan = json.loads((case / "plan.json").read_text())
    report = verify_capture(case)
    require(plan["environment"] == corpus.runtime, "Room plan runtime differs")
    require(
        report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256,
        "Room oracle/profile differs",
    )
    require(
        report["driver_sha256"]
        == corpus.manifest["as_run_sources"]["sources/protocol_capture.py.final.txt"],
        "Room recorder source differs",
    )
    if name in FAILED_REPORTS:
        _check_failed(case, name, corpus.manifest, report)
    else:
        _check_completed(corpus, name, plan, report)
    retained = corpus.tails[name]
    observation = reconcile(
        report,
        corpus.host,
        corpus.guest,
        {c: bytes.fromhex(v) for c, v in retained["host"].items()},
        guest_unread_output={c: bytes.fromhex(v) for c, v in retained["guest"].items()},
    )
    for view in ["host", "guest"]:
        for raw in retained[view].values():
            room, ids = identities(report)
            validate_tail(bytes.fromhex(raw), room, ids)
    return report, observation


def _check_failed(case: Path, name: str, manifest: dict, report: Report) -> None:
    """Check that a retained failure keeps its error, its progress and its plan.

    Parameters
    ----------
    case : Path
        The directory of the failed report.
    name : str
        The name of the failed report.
    manifest : dict
        The parsed manifest, which holds the frozen plan digests.
    report : Report
        The verified report of the failure.
    """
    prefix, completed = FAILED_REPORTS[name]
    require(
        report["status"] == "failed"
        and report["error"].startswith(prefix)
        and report["completed_actions"] == completed
        and sha(case / "plan.json") == manifest["frozen_failed_plans"][name],
        "Failed room expectation was erased/reclassified",
    )


def _check_completed(corpus: Corpus, name: str, plan: dict, report: Report) -> None:
    """Check a completed report against its plan, its request bytes and its meaning.

    Parameters
    ----------
    corpus : Corpus
        The files of the corpus.
    name : str
        The name of the completed report.
    plan : dict
        The parsed plan of the report.
    report : Report
        The verified report.
    """
    steps, expectation = corpus.expected[name]
    require(
        report["status"] == "completed"
        and plan["steps"] == steps
        and plan["expectation"] == expectation,
        "Room completed plan differs",
    )
    waits(report, steps)
    variables = _substitutions(name, report)
    _check_streams(report, steps, variables)
    if "room" in variables:
        semantic(name, report)
        _check_direct_acks(report, steps, variables)


def _substitutions(name: str, report: Report) -> dict[str, str]:
    """Return the hexadecimal values that replace the placeholders of a report.

    Parameters
    ----------
    name : str
        The name of the report.
    report : Report
        The verified report.

    Returns
    -------
    dict[str, str]
        The room and each owned user identifier, for a room scenario only.
    """
    variables: dict[str, str] = {}
    if name in ROOM_SCENARIOS:
        room, ids = identities(report)
        variables["room"] = room.hex()
        variables.update({label + "_uid": ids[label].hex() for label in cases.ROLES})
    return variables


def _substitute(value: str, variables: dict[str, str]) -> str:
    """Replace each ``{key}`` placeholder of ``value`` with its hexadecimal data.

    Parameters
    ----------
    value : str
        The hexadecimal text of a planned send step.
    variables : dict[str, str]
        The hexadecimal data of each placeholder.

    Returns
    -------
    str
        The text with every placeholder replaced.
    """
    for key, data in variables.items():
        value = value.replace("{" + key + "}", data)
    return value


def _check_streams(
    report: Report, steps: list[dict], variables: dict[str, str]
) -> None:
    """Check that the bytes sent on each connection match the planned sends.

    Parameters
    ----------
    report : Report
        The verified report.
    steps : list[dict]
        The planned steps.
    variables : dict[str, str]
        The hexadecimal data of each placeholder.
    """
    for connection, recorded in report["streams"].items():
        sent = ""
        for step in steps:
            if step["op"] != "send" or step["connection"] != connection:
                continue
            sent += _substitute(step["hex"], variables)
        require(sent == recorded["sent_hex"], "Room request bytes differ")


def _check_direct_acks(
    report: Report, steps: list[dict], variables: dict[str, str]
) -> None:
    """Check that no request of a room or settings kind was given a direct ACK.

    Parameters
    ----------
    report : Report
        The verified report.
    steps : list[dict]
        The planned steps.
    variables : dict[str, str]
        The hexadecimal data of each placeholder.
    """
    # No normal success ACK exists for these request kinds. Check each caller's
    # actual request IDs rather than notification IDs.
    for step in steps:
        if step["op"] != "send":
            continue
        raw = bytes.fromhex(_substitute(step["hex"], variables))
        if len(raw) < FRAME_HEADER_BYTES:
            continue
        request_frame = decode_frame(raw)
        if request_frame["type"] in ACKLESS_REQUESTS:
            require(
                not any(
                    f["is_reply"] and f["id"] == request_frame["id"]
                    for f in selected(report, step["connection"])
                ),
                "Invented room/settings direct ACK",
            )
