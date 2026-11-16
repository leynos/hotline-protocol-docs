"""Check the C56 as-run case of the isolated control witness."""

import typing as typ

import native_control_readiness as gates
from native_wire_names import (
    FIELD_OPTIONS,
    FIELD_USER_ID,
    TYPE_DOWNLOAD_FILE,
    TYPE_REFERENCE_CLEANUP,
    TYPE_UPLOAD_FILE,
)
from protocol_capture import decode_frame, verify_capture
from verify_native_ban_control_core import (
    CONTROL_PORT,
    EXPECTED,
    NS,
    PHASES,
    PID,
    START,
    Json,
    digest,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

HANDSHAKE_PREFIX = "54525450"  # ``TRTP``, the start of a session handshake
MIN_FRAME_HEX_CHARS = 40  # a frame header is 20 bytes
BAN_REQUEST = 110
BAN_ID = 33
BAN_OPTION = b"\0\2"
MOVEMENT_REQUESTS = {TYPE_DOWNLOAD_FILE, TYPE_UPLOAD_FILE, TYPE_REFERENCE_CLEANUP}
LAUNCH_PROPERTIES = (
    "--property=User=0",
    f"--property=NetworkNamespacePath=/proc/{PID}/ns/net",
    "--property=Type=oneshot",
    "--property=RuntimeMaxSec=180s",
)
UNIT_TERMINAL = (
    "Type=oneshot",
    "RemainAfterExit=yes",
    "MainPID=0",
    "Result=success",
    "ExecMainStatus=0",
)


def capture_scope(base: Path, ready: Json) -> None:
    """Check the as-run capture's identity and scope against the boot.

    Parameters
    ----------
    base : pathlib.Path
        The ``case-c56`` directory.
    ready : dict[str, typing.Any]
        The C55 readiness record.
    """
    capture = loaded(base / "capture-ready.json")
    need(
        capture["emulator_pid"] == PID
        and capture["emulator_starttime"] == START
        and capture["emulator_netns"] == NS
        and capture["emulator_sha256"] == EXPECTED["emulator"]
        and capture["owned_working_image"].endswith(
            "native-eventlab-one-01/working.dsk"
        )
        and capture["host_recorder_pid"] == ready["recorders"]["host"]["pid"]
        and capture["namespace_recorder_pid"] == ready["recorders"]["namespace"]["pid"]
        and capture["ns_routes"] == []
        and capture["primary_syn_count"] == 0
        and capture["fixture_profile"] == "control-only"
        and capture["full_file_baseline"] == "not_exercised",
        "As-run capture identity or scope differs",
    )


def controller(base: Path) -> None:
    """Check how the root controller was launched and how it exited.

    Parameters
    ----------
    base : pathlib.Path
        The ``case-c56`` directory.
    """
    launch = loaded(base / "controller-launch.json")
    argv = launch["argv"]
    need(
        launch["source_sha256"] == EXPECTED["controller"]
        and all(item in argv for item in LAUNCH_PROPERTIES)
        and argv[argv.index("--plans") + 1].endswith("native-ban-control-c56/plans")
        and argv[argv.index("--binary") + 1].endswith("HLserver19.pef"),
        "Controller root/namespace/source launch differs",
    )
    unit = (base / "controller-unit-terminal.txt").read_text()
    need(
        all(item in unit for item in UNIT_TERMINAL),
        "Controller managed exit differs",
    )


def phase_report(base: Path, hashes: Json, name: str, count: int) -> Json:
    """Check one phase's as-run plan and capture, and replay the capture.

    Parameters
    ----------
    base : pathlib.Path
        The ``case-c56`` directory.
    hashes : dict[str, typing.Any]
        The recorded digest of each plan.
    name : str
        The phase.
    count : int
        The number of actions that the phase's capture must have completed.

    Returns
    -------
    dict[str, typing.Any]
        The replayed capture report.
    """
    plan = base / "plans" / f"{name}.json"
    need(digest(plan) == hashes[name], f"{name} as-run source plan differs")
    prepared = loaded(plan)
    need(
        prepared["environment"]["emulator_pid"] == PID
        and prepared["environment"]["source_a7_sha256"] == EXPECTED["source_a7"]
        and prepared["environment"]["fixture_profile"] == "control-only"
        and prepared["environment"]["full_file_baseline"] == "not_exercised"
        and prepared["endpoints"]
        == {"control": {"host": "127.0.0.1", "port": CONTROL_PORT}},
        f"{name} plan profile/endpoint differs",
    )
    folder = base / "captures" / name
    need(digest(folder / "plan.json") == hashes[name], "Capture plan/source differs")
    report = verify_capture(folder)
    need(
        report["status"] == "completed" and report["completed_actions"] == count,
        f"{name} capture incomplete",
    )
    return report


def phase_reports(base: Path) -> dict[str, Json]:
    """Replay the capture of every phase.

    Parameters
    ----------
    base : pathlib.Path
        The ``case-c56`` directory.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        Each phase's report, by name.
    """
    hashes = loaded(base / "plans/source-hashes.json")
    need(set(hashes) == set(PHASES), "As-run plan inventory differs")
    reports = {}
    for name, count in PHASES.items():
        reports[name] = phase_report(base, hashes, name, count)
    return reports


def gate_reports(reports: dict[str, Json]) -> bytes:
    """Apply the control-readiness gates to the phase reports.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        Each phase's report.

    Returns
    -------
    bytes
        The target's user id, from the ban phase.
    """
    need(reports["ban"].get("controller_uid") == 0, "Guarded controller was not root")
    gates.readiness(reports["readiness"])
    gates.guarded_account(reports["guard"], absent=True)
    gates.guarded_account(reports["seed"], absent=False)
    target_uid = gates.target_gate(reports["ban"]["frames"])
    gates.outcome(reports["ban"])
    gates.probe(reports["probe"])
    return target_uid


def one_ban_scope(reports: dict[str, Json], target_uid: bytes) -> None:
    """Check that exactly one option-two ban was sent and no transfer was made.

    Parameters
    ----------
    reports : dict[str, dict[str, typing.Any]]
        Each phase's report.
    target_uid : bytes
        The target's user id.
    """
    sends = [
        decode_frame(bytes.fromhex(e["hex"]))
        for report in reports.values()
        for e in report["events"]
        if e["event"] == "send"
        and len(e["hex"]) >= MIN_FRAME_HEX_CHARS
        and e["hex"][:8] != HANDSHAKE_PREFIX
    ]
    bans = [item for item in sends if item["type"] == BAN_REQUEST]
    need(
        len(bans) == 1
        and bans[0]["id"] == BAN_ID
        and gates.fields(bans[0])
        == {FIELD_USER_ID: target_uid, FIELD_OPTIONS: BAN_OPTION}
        and all(item["type"] not in MOVEMENT_REQUESTS for item in sends),
        "Control-only request or one-ban scope differs",
    )


def case(corpus: Path, ready: Json) -> dict[str, Json]:
    """Check the C56 as-run case and replay its captures.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    ready : dict[str, typing.Any]
        The C55 readiness record.

    Returns
    -------
    dict[str, dict[str, typing.Any]]
        Each phase's replayed report, by name.
    """
    base = corpus / "case-c56"
    capture_scope(base, ready)
    controller(base)
    reports = phase_reports(base)
    target_uid = gate_reports(reports)
    one_ban_scope(reports, target_uid)
    return reports
