"""Check the readiness and postflight controls and the finite board case's report.

The board case's report is checked against its plan, its request composition, its
epoch and the boundaries of its posts. The composition uses the request types that
``native_board_cases`` plans, so a request that the plan does not make is refused.
"""

import typing as typ

from native_wire_names import TYPE_EMPTY_ACK, TYPE_LOGIN
from verify_native_board_checks import Report, need, read, sha, utc
from verify_native_board_pins import (
    BOARD,
    CASES,
    DATA,
    DEADLINE,
    PLAN,
    RUNNER,
)

if typ.TYPE_CHECKING:
    from pathlib import Path
    from types import ModuleType

NO_ERROR = ""  # the error text of a report that did not fail
COMPLETED_ACTIONS = 18  # the actions that a generic control completes
FRAME_COUNT = 71  # the frames of the finite board case's report
EVENT_COUNT = 429  # the events of the finite board case's report
BYTE_COUNT = 463467  # the bytes of the finite board case's report
BOARD_READ = 101  # the request type of a board read, as the plan makes it
BOARD_POST = 103  # the request type of a board post, as the plan makes it
GREETING_BYTES = 12  # the TRTP greeting that opens each stream
REQUEST_HEADER_BYTES = 20  # the header of a numbered request
REQUEST_SIZE_START = 16  # where the data size sits in a numbered request header
KIND_BYTES = 4  # the leading bytes of a numbered request that name its type
SEGMENT_COUNT = 12  # the successful posts' segments of the board
POST_COUNT = 13  # the posts of the finite board case
POST_SIZES = [0, 7, 7, 8191, 8192, 8192, 8192, 8192, 8192, 8192, 7155, 1, 8193]
REQUEST_COUNTS = {TYPE_LOGIN: 4, BOARD_READ: 9, BOARD_POST: 13, TYPE_EMPTY_ACK: 6}


def check_control(
    raw: Path, phase: str, capture: ModuleType, readiness: ModuleType
) -> None:
    """Check one generic control, then the readiness of its report.

    Parameters
    ----------
    raw : pathlib.Path
        The raw directory of the corpus.
    phase : str
        The control's name, which is also its directory.
    capture : types.ModuleType
        The capture module, which verifies the control's folder.
    readiness : types.ModuleType
        The readiness module, which checks the verified report.
    """
    folder = raw / phase
    report = capture.verify_capture(folder)
    need(
        report["status"] == "completed"
        and report["completed_actions"] == COMPLETED_ACTIONS
        and sha(folder / "plan.json") == sha(raw / "control-plans/readiness.json")
        and (raw / f"{phase}.exit").read_text().strip() == "0",
        f"{phase} generic control differs",
    )
    readiness.readiness(report)


def check_numbered_requests(report: Report, plan: Report) -> None:
    """Check each stream's greeting and numbered requests against the plan's types.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The finite board case's report.
    plan : dict[str, typing.Any]
        The generated board plan, which names the greeting.
    """
    counts = {TYPE_LOGIN: 0, BOARD_READ: 0, BOARD_POST: 0, TYPE_EMPTY_ACK: 0}
    for stream in report["streams"].values():
        sent = bytes.fromhex(stream["sent_hex"])
        need(
            sent[:GREETING_BYTES] == bytes.fromhex(plan["hello_hex"]),
            "Board greeting differs",
        )
        pending = sent[GREETING_BYTES:]
        while pending:
            need(len(pending) >= REQUEST_HEADER_BYTES, "Short numbered request")
            size = int.from_bytes(
                pending[REQUEST_SIZE_START:REQUEST_HEADER_BYTES], "big"
            )
            need(
                len(pending) >= REQUEST_HEADER_BYTES + size,
                "Truncated numbered request",
            )
            kind = int.from_bytes(pending[:KIND_BYTES], "big")
            need(kind in counts, "Unexpected numbered request kind")
            counts[kind] += 1
            pending = pending[REQUEST_HEADER_BYTES + size :]
    need(counts == REQUEST_COUNTS, "32-request composition differs")


def check_posts(report: Report) -> None:
    """Check the segment count, the post sizes and the rejected post's read.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The finite board case's report.
    """
    need(
        len(report["segments_hex"]) == SEGMENT_COUNT
        and len(report["post_data_hex"]) == POST_COUNT
        and [len(bytes.fromhex(x)) for x in report["post_data_hex"]] == POST_SIZES
        and report["reads"]["12"] == report["reads"]["11"]
        and report["whole_board_sha256"] == BOARD,
        "Post boundaries, rejected 8193 or stored prefix differs",
    )


def reports(corpus: Path, modules: tuple[ModuleType, ...], plan: Report) -> Report:
    """Check the controls and the finite board case's report.

    Returns
    -------
    dict[str, typing.Any]
        The finite board case's report, once its checks pass.
    """
    raw = corpus / "raw"
    board, _, readiness, capture, _ = modules
    for phase in ("readiness", "postflight"):
        check_control(raw, phase, capture, readiness)
    report = read(raw / "coordinator/report.json")
    need(
        report["status"] == "completed"
        and report["error"] == NO_ERROR
        and report["plan_sha256"] == PLAN
        and report["capture_receipt_sha256"] == sha(raw / "capture-ready.json")
        and report["native_source_sha256"] == DATA
        and report["runner_sha256"] == RUNNER
        and report["producer_sha256"] == CASES
        and (raw / "coordinator.exit").read_text().strip() == "0"
        and len(report["frames"]) == FRAME_COUNT
        and len(report["events"]) == EVENT_COUNT
        and report["byte_count"] == BYTE_COUNT,
        "Finite custom board case or source binding differs",
    )
    board.verify_report(plan, report)
    check_numbered_requests(report, plan)
    need(
        utc(report["started_utc"])
        >= utc(read(raw / "capture-ready.json")["epoch_started_utc"])
        and utc(report["ended_utc"]) < utc(DEADLINE),
        "Board case ran outside fixed epoch",
    )
    check_posts(report)
    return report
