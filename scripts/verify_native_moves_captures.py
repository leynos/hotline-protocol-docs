"""Load the planned cases of the move corpus and verify each capture against them.

verify_native_moves imports these functions, and the names stay importable from it.
"""

import json
import typing as typ

from native_move_cases import (
    cleanup,
    deletions,
    finalization,
    moves,
    preflight,
    seed,
)
from native_packet_evidence import reconcile
from pcap_tcp import read_packets
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_core import require
from verify_native_mkdir import creation_quiet
from verify_native_shx import sha

if typ.TYPE_CHECKING:
    from pathlib import Path

    from native_move_cases import Cases

__all__ = [
    "check_inventory",
    "expected_cases",
    "read_corpus_packets",
    "run_captures",
]

type Report = dict[str, typ.Any]
type Packets = list[dict[str, typ.Any]]

# The packets that the retained host capture holds.
HOST_CAPTURE_PACKETS = 1875


def expected_cases() -> Cases:
    """Plan every case of the corpus, keyed by the directory that holds it.

    Returns
    -------
    dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The preflight, seed, final and cleanup plans, then each move and deletion.
    """
    expected = {
        "preflight": next(iter(preflight().values())),
        "seed": next(iter(seed().values())),
        "final": next(iter(finalization().values())),
        "cleanup": next(iter(cleanup().values())),
    }
    expected.update({"moves/" + k: v for k, v in moves().items()})
    expected.update({"deletions/" + k: v for k, v in deletions().items()})
    return expected


def check_inventory(directory: Path, manifest: Report, expected: Cases) -> None:
    """Check that the manifest and the directory list the same reports.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    expected : dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The planned cases from ``expected_cases``.
    """
    require(
        set(manifest["reports"])
        == set(expected)
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "Move report inventory differs",
    )


def read_corpus_packets(directory: Path, manifest: Report) -> tuple[Packets, Packets]:
    """Read the host and guest captures and check their packet inventory.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.

    Returns
    -------
    tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The host packets and the guest packets.
    """
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    require(
        len(host) == manifest["host_capture_packets"] == HOST_CAPTURE_PACKETS
        and manifest["host_kernel_drops"] == 0,
        "Move packet inventory differs",
    )
    return host, guest


def _read_plan(
    case: Path, case_spec: tuple[list[typ.Any], dict[str, typ.Any]]
) -> Report:
    """Read the as-run plan of one case and check it against the planned one.

    Parameters
    ----------
    case : pathlib.Path
        The directory of the case.
    case_spec : tuple[list[typing.Any], dict[str, typing.Any]]
        The planned steps and expectation.

    Returns
    -------
    dict[str, typing.Any]
        The parsed ``plan.json``.
    """
    steps, expectation = case_spec
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Move as-run plan differs",
    )
    return plan


def _capture(case: Path, packets: tuple[Packets, Packets], sources: set[str]) -> Report:
    """Verify one capture's provenance and reconcile it with the packet records.

    Parameters
    ----------
    case : pathlib.Path
        The directory of the case.
    packets : tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The host and guest packets.
    sources : set[str]
        The digests of the driver sources retained for the corpus.

    Returns
    -------
    dict[str, typing.Any]
        The verified capture report.
    """
    host, guest = packets
    report = verify_capture(case)
    require(
        report["status"] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"] in sources,
        "Move capture provenance/completion differs",
    )
    reconcile(report, host, guest)
    return report


def run_captures(
    directory: Path, expected: Cases, packets: tuple[Packets, Packets]
) -> tuple[dict[str, Report], int]:
    """Verify every case capture and count the paired connections.

    Parameters
    ----------
    directory : pathlib.Path
        The corpus directory.
    expected : dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The planned cases from ``expected_cases``.
    packets : tuple[list[dict[str, typing.Any]], list[dict[str, typing.Any]]]
        The host and guest packets.

    Returns
    -------
    tuple[dict[str, dict[str, typing.Any]], int]
        The verified report of each case, and the number of paired connections.
    """
    sources = {sha(p) for p in (directory / "sources").iterdir()}
    reports: dict[str, Report] = {}
    connections = 0
    for key, case_spec in expected.items():
        plan = _read_plan(directory / key, case_spec)
        report = _capture(directory / key, packets, sources)
        connections += len(report["streams"])
        reports[key] = report
        if key.startswith(("moves/", "deletions/")):
            creation_quiet(report, plan)
    return reports, connections
