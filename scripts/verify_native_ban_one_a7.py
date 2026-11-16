"""Replay the A7 baseline of the option-one native ban witness from frozen files."""

import typing as typ

from native_filp import decode, metadata
from native_wire_names import (
    FIELD_FILE_CREATOR,
    FIELD_FILE_NAME,
    FIELD_FILE_SIZE,
    FIELD_FILE_TYPE,
    FIELD_TRANSFER_SIZE,
)
from protocol_capture import verify_capture
from verify_native_ban_one_core import (
    A7_ACTIONS,
    A7_FILE_SIZE,
    A7_FILES,
    A7_TRANSFER_BYTES,
    BASE_PLAN_SHA,
    FILE_KIND_FIELD,
    digest,
    fields,
    frame,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]


def _check_plan(fixture: Path) -> None:
    """Check the as-run plan of the A7 baseline against its original plan.

    Parameters
    ----------
    fixture : pathlib.Path
        The fixture directory of the corpus.
    """
    original = loaded(fixture / "a7-original-plan.json")
    plan = loaded(fixture / "a7-as-run-plan.json")
    need(
        digest(fixture / "a7-original-plan.json") == BASE_PLAN_SHA,
        "A7 plan source differs",
    )
    for key in original.keys() - {"environment", "endpoints"}:
        need(original[key] == plan[key], f"A7 {key} changed")
    need(len(plan["steps"]) == A7_ACTIONS, "A7 action count differs")
    need(
        plan["endpoints"]
        == {
            "control": {"host": "127.0.0.1", "port": 15720},
            "data": {"host": "127.0.0.1", "port": 15721},
        },
        "A7 lab endpoints differ",
    )


def _check_baseline(corpus: Path, report: Report) -> None:
    """Check the baseline replies, the Files listing and the transfer ACK.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    report : dict[str, typing.Any]
        The verified A7 capture report.
    """
    reference = loaded(corpus / "reference/diagnostic-preflight-report.json")
    for identifier in (10, 11):
        value = frame(report, "a", identifier)
        need(
            value["error"] == 0
            and value["fields"] == frame(reference, "a", identifier)["fields"],
            f"A7 baseline reply {identifier} differs",
        )
    need(len(frame(report, "a", 11)["fields"]) == A7_FILES, "A7 Files count differs")
    info = fields(frame(report, "a", 12))
    need(
        {
            key: info[key]
            for key in (
                FIELD_FILE_NAME,
                FILE_KIND_FIELD,
                FIELD_FILE_CREATOR,
                FIELD_FILE_SIZE,
                FIELD_FILE_TYPE,
            )
        }
        == {
            FIELD_FILE_NAME: b"mothra-race-fixture",
            FILE_KIND_FIELD: b"Text File",
            FIELD_FILE_CREATOR: b"MOTH",
            FIELD_FILE_SIZE: bytes.fromhex("0010013d"),
            FIELD_FILE_TYPE: b"TEXT",
        },
        "A7 metadata differs",
    )
    need(
        frame(report, "a", 14)["fields"] == frame(report, "a", 17)["fields"],
        "A7 idle 303 changed",
    )
    ack = fields(frame(report, "a", 15))
    need(
        ack[FIELD_TRANSFER_SIZE] == A7_TRANSFER_BYTES.to_bytes(4, "big")
        and ack[FIELD_FILE_SIZE] == A7_FILE_SIZE.to_bytes(4, "big"),
        "A7 fork sizes differ",
    )


def _check_transfer(report: Report, mothra: Path) -> int:
    """Check the FILP transfer of the A7 baseline against the reference forks.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The verified A7 capture report.
    mothra : pathlib.Path
        The root of the mothra checkout that holds the reference forks.

    Returns
    -------
    int
        The length of the FILP transfer in bytes.
    """
    transfer = bytes.fromhex(report["streams"]["download"]["received_hex"])
    need(len(transfer) == A7_TRANSFER_BYTES, "A7 FILP length differs")
    forks = decode(transfer)
    old = mothra / "evidence/gap-remediation/2026-11-12/native-cleanup-01/native-files"
    need(
        forks["DATA"] == (old / "mothra-race-fixture.data").read_bytes(),
        "A7 DATA differs",
    )
    need(
        forks["MACR"] == (old / "mothra-race-fixture.rsrc").read_bytes(),
        "A7 RSRC differs",
    )
    meta = metadata(forks["INFO"])
    need(
        (meta["type"], meta["creator"], meta["name"], meta["comment"])
        == (b"TEXT", b"MOTH", b"mothra-race-fixture", b"fixture-comment"),
        "A7 INFO differs",
    )
    return len(transfer)


def verify_a7(corpus: Path, mothra: Path) -> dict[str, typ.Any]:
    """Replay the A7 baseline of the witness and return its counts.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    mothra : pathlib.Path
        The root of the mothra checkout that holds the reference forks.

    Returns
    -------
    dict[str, typing.Any]
        The action, account, file and FILP byte counts of the baseline.
    """
    fixture = corpus / "fixture"
    _check_plan(fixture)
    report = verify_capture(fixture / "a7-capture")
    need(
        report["status"] == "completed" and report["completed_actions"] == A7_ACTIONS,
        "A7 incomplete",
    )
    _check_baseline(corpus, report)
    filp_bytes = _check_transfer(report, mothra)
    return {
        "actions": A7_ACTIONS,
        "accounts": 2,
        "files": A7_FILES,
        "filp_bytes": filp_bytes,
    }
