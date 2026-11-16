"""Check the capture of each case of the boundary corpus against its plan."""

import dataclasses as dc
import json
import typing as typ

from native_packet_evidence import reconcile
from protocol_capture import ORACLE_SHA256, verify_capture
from verify_native_article_deletion import measured_wait
from verify_native_auth import reply
from verify_native_core import require
from verify_native_news_boundary_data import REFERENCE_FIELD
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]
type Case = tuple[list[dict[str, typ.Any]], dict[str, typ.Any]]


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The parts of a boundary corpus that the case checks all read.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    runtime : dict[str, typing.Any]
        The recorded runtime identity.
    host : list[dict[str, typing.Any]]
        The packets of the host recorder.
    guest : list[dict[str, typing.Any]]
        The packets of the guest recorder.
    sources : set[str]
        The digests of the driver sources that the corpus retains.
    """

    directory: Path
    manifest: Report
    runtime: Report
    host: list[Report]
    guest: list[Report]
    sources: set[str]


def check_case(
    corpus: Corpus,
    key: str,
    steps: list[dict[str, typ.Any]],
    expectation: dict[str, typ.Any],
) -> Report:
    """Check the capture of one case against its plan and return its report.

    Parameters
    ----------
    corpus : Corpus
        The corpus under verification.
    key : str
        The name of the case, which is also its directory.
    steps : list[dict[str, typing.Any]]
        The planned steps of the case.
    expectation : dict[str, typing.Any]
        The planned expectation of the case.

    Returns
    -------
    dict[str, typing.Any]
        The verified capture report of the case.
    """
    case = corpus.directory / key
    plan = json.loads((case / "plan.json").read_text())
    require(
        plan["steps"] == steps
        and plan["expectation"] == expectation
        and plan["environment"] == corpus.runtime,
        "Boundary as-run plan differs",
    )
    report = verify_capture(case)
    require(
        report["status"] == corpus.manifest["reports"][key] == "completed"
        and report["profile"] == "native-mac-oracle"
        and report["oracle_sha256"] == ORACLE_SHA256
        and report["driver_sha256"] in corpus.sources
        and all(f["error"] == 0 for f in report["frames"]),
        "Boundary capture completion/provenance differs",
    )
    reference = (
        fields(reply(report, 80))[REFERENCE_FIELD].hex()
        if key in {"final", "publish"}
        else ""
    )
    check_streams(report, steps, reference)
    reconcile(report, corpus.host, corpus.guest)
    return report


def check_streams(
    report: Report, steps: list[dict[str, typ.Any]], reference: str
) -> None:
    """Check that each recorded request is the planned request of its connection.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified capture report of the case.
    steps : list[dict[str, typing.Any]]
        The planned steps of the case.
    reference : str
        The hexadecimal reference that replaces ``{ref80}`` in the steps.
    """
    for connection, recorded in report["streams"].items():
        sent = "".join(
            bytes.fromhex(s["hex"].replace("{ref80}", reference)).hex()
            for s in steps
            if s["op"] == "send" and s["connection"] == connection
        )
        require(
            recorded["sent_hex"] == sent,
            "Boundary recorded request differs from plan",
        )


def check_cases(
    corpus: Corpus, expected: dict[str, Case]
) -> tuple[dict[str, Report], int]:
    """Check every case in order and count the connections of the corpus.

    Parameters
    ----------
    corpus : Corpus
        The corpus under verification.
    expected : dict[str, tuple[list[dict[str, typing.Any]], dict[str, typing.Any]]]
        The planned steps and expectation of each case, in order.

    Returns
    -------
    tuple[dict[str, dict[str, typing.Any]], int]
        The verified report of each case, by name, and the connection count.
    """
    reports: dict[str, Report] = {}
    connections = 0
    for key, (steps, expectation) in expected.items():
        report = check_case(corpus, key, steps, expectation)
        connections += len(report["streams"])
        reports[key] = report
        if key == "seed" or key.startswith("append-"):
            measured_wait(report, "pause")
    return reports, connections
