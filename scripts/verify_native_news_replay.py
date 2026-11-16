"""Replay the news case expectations and check each capture, plan and packet set."""

import json
import typing as typ

from native_news_cases import (
    bodies,
    cleanup,
    files_preflight,
    finalization,
    listings,
    posts,
    preflight,
    publish_cleanup,
    remove_publisher,
    seed,
    structures,
    thread_children,
    thread_grandchild,
)
from native_packet_evidence import reconcile
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_core import require
from verify_native_mkdir import creation_quiet
from verify_native_news_data import EMULATOR_PID, HOST_PACKET_COUNT, RUNNING_SHA256

if typ.TYPE_CHECKING:
    from pathlib import Path

type Packets = list[dict[str, typ.Any]]
type Expectation = dict[str, tuple[typ.Any, typ.Any]]

CHILDREN_PARENT = 1  # the article under which the two children are posted
GRANDCHILD_PARENT = 4  # the article under which the grandchild is posted


def check_runtime(directory: Path) -> None:
    """Check that the runtime record names the emulator and executable expected."""
    runtime = json.loads((directory / "runtime-check.json").read_text())
    require(
        runtime["emulator_pid"] == EMULATOR_PID
        and runtime["running_executable_sha256"] == RUNNING_SHA256,
        "News runtime identity differs",
    )


def expected_cases() -> Expectation:
    """Build the expected step list and expectation of every news case.

    Returns
    -------
    dict[str, tuple[typ.Any, typ.Any]]
        Each case name, with its steps and expectation, in verification order.
    """
    factories = {
        "preflight": preflight,
        "seed": seed,
        "posts": posts,
        "files-preflight": files_preflight,
        "files-after": files_preflight,
        "final": finalization,
        "cleanup": cleanup,
        "publish": publish_cleanup,
        "remove-publisher": remove_publisher,
    }
    expected = {k: next(iter(f().values())) for k, f in factories.items()}
    expected["children"] = next(iter(thread_children(CHILDREN_PARENT).values()))
    expected["grandchild"] = next(iter(thread_grandchild(GRANDCHILD_PARENT).values()))
    for group, cases in [
        ("listings", listings()),
        ("structures", structures()),
        ("bodies", bodies()),
    ]:
        expected.update({group + "/" + k: v for k, v in cases.items()})
    return expected


def check_inventory(directory: Path, manifest: dict, expected: Expectation) -> None:
    """Check that the expected cases, the manifest and the corpus agree."""
    require(
        set(expected)
        == set(manifest["reports"])
        == {
            str(p.parent.relative_to(directory)) for p in directory.rglob("report.json")
        },
        "News report inventory differs",
    )


def check_packets(manifest: dict, host: Packets) -> None:
    """Check the host packet count and that the recorder dropped nothing."""
    require(
        len(host) == manifest["host_capture_packets"] == HOST_PACKET_COUNT
        and manifest["host_kernel_drops"] == 0,
        "News packet recorder inventory differs",
    )


def replay_cases(
    directory: Path,
    expected: Expectation,
    sources: set[str],
    packets: tuple[Packets, Packets],
) -> tuple[dict[str, dict], int]:
    """Verify each case's plan and capture, and reconcile its packets.

    Returns
    -------
    tuple[dict[str, dict], int]
        The verified report of each case, and the number of paired connections.
    """
    host, guest = packets
    reports: dict[str, dict[str, typ.Any]] = {}
    connections = 0
    for key, (steps, expectation) in expected.items():
        case = directory / key
        plan = json.loads((case / "plan.json").read_text())
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "News as-run plan differs",
        )
        report = verify_capture(case)
        require(
            report["status"] == "completed"
            and report["profile"] == "native-mac-oracle"
            and report["oracle_sha256"] == ORACLE_SHA256
            and report["driver_sha256"] in sources,
            "News capture provenance/completion differs",
        )
        reconcile(report, host, guest)
        connections += len(report["streams"])
        reports[key] = report
        if key.startswith(("listings/", "structures/", "bodies/")) or key == "posts":
            creation_quiet(report, plan)
    return reports, connections
