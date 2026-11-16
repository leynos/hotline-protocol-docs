"""Check the paired captures of article deletion: their inputs, plans and phases.

The checks run in the order that the original verifier ran them: the packets
and runtimes first, then each capture's plan, provenance, streams and packets,
then the chronology and the retained failed phases.
"""

import dataclasses as dc
import datetime as dt
import json
import typing as typ
from itertools import pairwise

from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_article_deletion_checks import error
from verify_native_article_deletion_data import (
    BURST_ACTIONS,
    BURST_MAX_ELAPSED_NS,
    BURST_REPLIES,
    INITIAL_EMULATOR_PID,
    NATIVE_CATALOG_ID,
    NATIVE_EXECUTABLE_SHA256,
    NATIVE_RESOURCE_SHA256,
    RECOVERY_EMULATOR_PID,
)
from verify_native_auth import reply
from verify_native_core import require
from verify_native_shx import fields, sha

if typ.TYPE_CHECKING:
    from pathlib import Path

    from native_plan import Action
    from verify_native_article_deletion_plans import Expected


@dc.dataclass(frozen=True, slots=True)
class CaptureInputs:
    """The inputs that every capture is checked against.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the corpus.
    packets : dict[str, tuple[list[typing.Any], list[typing.Any]]]
        The host and guest packets of the initial and recovery phases.
    sources : set[str]
        The SHA-256 digests of the files in the ``sources`` directory.
    runtimes : dict[str, dict[str, typing.Any]]
        The runtime record of the initial and recovery phases.
    """

    directory: Path
    manifest: dict[str, typ.Any]
    packets: dict[str, tuple[list[typ.Any], list[typ.Any]]]
    sources: set[str]
    runtimes: dict[str, dict[str, typ.Any]]


def _read_packets(directory: Path) -> dict[str, tuple[list[typ.Any], list[typ.Any]]]:
    """Read the host and guest packets of both phases and check the host counts.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, tuple[list[typing.Any], list[typing.Any]]]
        The host and guest packets, keyed by ``initial`` and ``recovery``.
    """
    packets: dict[str, tuple[list[typ.Any], list[typ.Any]]] = {}
    for phase, suffix, count in [("initial", "", 321), ("recovery", "-recovery", 2198)]:
        host = read_packets(directory / ("host" + suffix + ".pcap"))
        guest = read_packets(
            directory
            / ("guest-initial.pcap" if phase == "initial" else "guest-recovery.pcap")
        )
        require(len(host) == count, "Deletion host packet count differs")
        packets[phase] = (host, guest)
    return packets


def read_capture_inputs(directory: Path, manifest: dict[str, typ.Any]) -> CaptureInputs:
    """Read the packets, sources and runtimes of the corpus and check them.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json`` of the corpus.

    Returns
    -------
    CaptureInputs
        The inputs that the captures are checked against.
    """
    packets = _read_packets(directory)
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    runtimes = {
        "initial": json.loads((directory / "runtime.json").read_text()),
        "recovery": json.loads((directory / "runtime-recovery.json").read_text()),
    }
    require(
        runtimes["initial"]["emulator_pid"] == INITIAL_EMULATOR_PID
        and runtimes["recovery"]["emulator_pid"] == RECOVERY_EMULATOR_PID
        and all(
            r["running_executable_sha256"] == NATIVE_EXECUTABLE_SHA256
            for r in runtimes.values()
        ),
        "Deletion runtime identities differ",
    )
    application = json.loads(
        (directory / "recovery-application-identity.json").read_text()
    )
    require(
        application["catalog"] == NATIVE_CATALOG_ID
        and application["data_sha256"] == ORACLE_SHA256
        and application["resource_sha256"] == NATIVE_RESOURCE_SHA256,
        "Recovery native application identity differs",
    )
    return CaptureInputs(
        directory=directory,
        manifest=manifest,
        packets=packets,
        sources=sources,
        runtimes=runtimes,
    )


def _check_provenance(report: dict, key: str, inputs: CaptureInputs) -> None:
    """Check the status, profile, oracle and driver of one capture.

    Parameters
    ----------
    report : dict
        The verified report of the capture.
    key : str
        The capture key, such as ``initial/burst``.
    inputs : CaptureInputs
        The inputs that the captures are checked against.
    """
    status = (
        "failed" if key in {"initial/burst", "initial/banned-login"} else "completed"
    )
    require(
        report["status"] == inputs.manifest["reports"][key] == status
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"] in inputs.sources,
        "Deletion capture provenance differs",
    )


def _check_streams(report: dict, key: str, steps: list[Action]) -> None:
    """Check that each recorded stream holds the executed prefix of its plan.

    Parameters
    ----------
    report : dict
        The verified report of the capture.
    key : str
        The capture key, which selects the reference of the final requests.
    steps : list[Action]
        The planned steps of the capture.
    """
    for connection, recorded in report["streams"].items():
        reference = (
            fields(reply(report, 80))[107].hex() if key in {"final", "publish"} else ""
        )
        sent = "".join(
            bytes.fromhex(step["hex"].replace("{ref80}", reference)).hex()
            for step in steps[: report["completed_actions"]]
            if step["op"] == "send" and step["connection"] == connection
        )
        require(
            recorded["sent_hex"] == sent,
            "Recorded requests differ from executed plan prefix",
        )


def _check_capture(
    inputs: CaptureInputs,
    key: str,
    entry: tuple[list[Action], dict[str, typ.Any]],
) -> dict:
    """Check one capture against its plan, its provenance and its packets.

    Parameters
    ----------
    inputs : CaptureInputs
        The inputs that the captures are checked against.
    key : str
        The capture key, such as ``deletions/leaf-one``.
    entry : tuple[list[Action], dict[str, typing.Any]]
        The expected steps and expectation of the capture.

    Returns
    -------
    dict
        The verified report of the capture.
    """
    steps, expectation = entry
    case = inputs.directory / key
    phase = "initial" if key.startswith("initial/") else "recovery"
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["environment"] == inputs.runtimes[phase],
        "As-run runtime provenance differs",
    )
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Deletion as-run plan differs",
    )
    report = verify_capture(case)
    _check_provenance(report, key, inputs)
    _check_streams(report, key, steps)
    reconcile(report, *inputs.packets[phase])
    return report


def check_captures(
    inputs: CaptureInputs,
    expected: Expected,
) -> tuple[dict[str, dict], int]:
    """Check every capture and count its paired connections.

    Parameters
    ----------
    inputs : CaptureInputs
        The inputs that the captures are checked against.
    expected : Expected
        The expected steps and expectation of each capture, keyed by its path.

    Returns
    -------
    tuple[dict[str, dict], int]
        The verified report of each capture, and the total of its connections.
    """
    reports: dict[str, dict] = {}
    connections = 0
    for key, entry in expected.items():
        report = _check_capture(inputs, key, entry)
        connections += len(report["streams"])
        reports[key] = report
    return reports, connections


def check_phases(
    reports: dict[str, dict],
    specifications: list[dict[str, typ.Any]],
) -> None:
    """Check the chronology of the captures and the retained failed phases.

    Parameters
    ----------
    reports : dict[str, dict]
        The verified report of each capture.
    specifications : list[dict[str, typing.Any]]
        The specifications from ``native_news_delete_cases.specs``.
    """
    chronology = (
        [
            "initial/preflight",
            "initial/burst",
            "initial/banned-login",
            "inventory-recovery",
        ]
        + ["resumed/" + s["case"] for s in specifications]
        + ["deletions/" + s["case"] for s in specifications]
        + ["final", "cleanup", "publish", "remove-publisher"]
    )
    require(
        all(
            dt.datetime.fromisoformat(reports[a]["recorded_at_utc"])
            <= dt.datetime.fromisoformat(reports[b]["started_at_utc"])
            for a, b in pairwise(chronology)
        ),
        "Deletion phase chronology differs",
    )
    burst = reports["initial/burst"]
    require(
        burst["completed_actions"] == BURST_ACTIONS
        and len([f for f in burst["frames"] if f["is_reply"]]) == BURST_REPLIES
        and all(f["error"] == 0 for f in burst["frames"])
        and burst["events"][-1]["elapsed_ns"] < BURST_MAX_ELAPSED_NS
        and "EOFError" in burst["error"],
        "Retained flood burst differs",
    )
    error(
        reply(reports["initial/banned-login"], 1),
        b"You are temporarily banned on this server.",
    )
