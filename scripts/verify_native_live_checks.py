"""Check the accounts, files, restart journal and oracle of the live corpus.

These checks run after every report has been replayed against its plan. The
order of the checks in each function is the order in which a corrupt corpus is
refused.
"""

import datetime as dt
import json
import typing as typ

from native_auth_cases import complement
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
)
from protocol_capture import ORACLE_SHA256
from verify_native_account_updates import enumeration
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

LOGIN_FRAMES = [(0, 0), (354, 0), (109, 0), (0, 0)]  # type and error of each frame
LIVE_FIELDS = {
    FIELD_NAME: b"Stored Beta27",
    FIELD_LOGIN: complement(b"m-live27"),
    FIELD_PASSWORD: b"x",  # a stand-in: the reply carries a password only as a flag
    FIELD_ACCESS_BITMAP: bytes(8),
}
MISSING = {FIELD_ERROR_TEXT: b"No account with login \xd2m-delete27\xd3."}
BASELINE_ACCOUNTS = 2
FILES_BASELINE = 41
LISTING_ID = 21
ENUMERATION_ID = 20
PERSISTENCE_REPORTS = ["before-final", "after-inspect", "after-inspect-confirmation"]
UI_COMMANDS = [
    ["click", "500", "350"],
    ["click", "285", "39"],
    ["click", "936", "248"],
    ["click", "408", "234"],
    ["key", "Alt_L+o"],
    ["click", "629", "310"],
]
HOST_EXIT_CODE = 143
COMPLETE_AFTER_EXIT = [
    "after-inspect",
    "after-login-old",
    "after-login-intermediate",
    "after-login-final",
    "after-login-deleted",
]
ORACLE_QUERIES = 16
ORACLE_ADDRESSES = {
    "10014df0",
    "100149e0",
    "10005d30",
    "10005f90",
    "10004f30",
    "10011870",
    "10007340",
    "100073c0",
    "100075e0",
    "10007ad0",
    "10018620",
    "10058400",
    "10058320",
    "1006db60",
    "10073f70",
    "10070700",
}


def check_logins(reports: dict[str, Report]) -> None:
    """Check that the final password logs in and the old and deleted ones do not."""
    for key, report in reports.items():
        if "-login-" not in key:
            continue
        frame = reply(report, 1)
        if key.endswith("-final"):
            require(
                [(f["type"], f["error"]) for f in report["frames"]] == LOGIN_FRAMES
                and fields(report["frames"][1]) == {FIELD_ACCESS_BITMAP: bytes(8)},
                "Persisted password/access login differs",
            )
        else:
            require(
                len(report["frames"]) == 1
                and frame["error"] == 1
                and fields(frame) == {FIELD_ERROR_TEXT: b"Incorrect login."},
                "Old/deleted reconnect result differs",
            )


def check_persistence(reports: dict[str, Report]) -> None:
    """Check that the edited and deleted accounts persisted across the restart."""
    for key in PERSISTENCE_REPORTS:
        require(
            reply(reports[key], 10)["error"] == 0
            and fields(reply(reports[key], 10)) == LIVE_FIELDS
            and reply(reports[key], 11)["error"] == 1
            and fields(reply(reports[key], 11)) == MISSING,
            "Account replacement/deletion did not persist across restart",
        )


def check_baseline(reports: dict[str, Report]) -> list[str]:
    """Check that the owned accounts were absent and the seed succeeded.

    Returns
    -------
    list[str]
        The baseline enumeration, which is the original accounts.
    """
    baseline = enumeration(reply(reports["preflight"], 10))
    for identifier, key in [(20, b"m-live27"), (21, b"m-delete27")]:
        require(
            reply(reports["preflight"], identifier)["error"] == 1
            and fields(reply(reports["preflight"], identifier))
            == {FIELD_ERROR_TEXT: b"No account with login \xd2" + key + b"\xd3."},
            "Owned live account was not initially absent",
        )
    require(
        all(f["error"] == 0 for f in reports["seed"]["frames"]),
        "Live account seed failed",
    )
    return baseline


def check_enumerations(reports: dict[str, Report], baseline: list[str]) -> None:
    """Check that the restart left the account enumeration unchanged."""
    require(
        len(baseline) == BASELINE_ACCOUNTS
        and enumeration(reply(reports["before-final"], ENUMERATION_ID))
        == enumeration(reply(reports["after-inspect"], ENUMERATION_ID))
        == enumeration(reply(reports["after-inspect-confirmation"], ENUMERATION_ID)),
        "Restart changed account enumeration",
    )


def check_files(reports: dict[str, Report], baseline: list[str]) -> None:
    """Check the Files listings after the restart and after each cleanup stage."""
    files = listing(reply(reports["preflight"], 11))
    require(len(files) == FILES_BASELINE, "Live Files baseline differs")
    for key in ["after-inspect", "after-inspect-confirmation"]:
        observed = listing(reply(reports[key], LISTING_ID))
        require(b"m-live27-flush" in observed, "Persisted live flush object missing")
        observed.pop(b"m-live27-flush")
        require(observed == files, "Restart changed unrelated Files entries")
    for key in ["cleanup", "publish", "remove-publisher"]:
        require(
            enumeration(reply(reports[key], ENUMERATION_ID)) == baseline,
            "Live account cleanup did not restore baseline",
        )
        after = listing(reply(reports[key], LISTING_ID))
        if key == "publish":
            require(b"m-live27-publish" in after, "Live publisher missing")
            after.pop(b"m-live27-publish")
        require(after == files, "Live helper cleanup did not restore Files")


def check_restart_journal(directory: Path, reports: dict[str, Report]) -> None:
    """Check the controlled quit and relaunch journal and the order of its steps."""
    ui = [
        json.loads(line)
        for line in (directory / "ui-events.jsonl").read_text().splitlines()
    ]
    require(
        [e["command"][2:] for e in ui] == UI_COMMANDS
        and all(e["exit_code"] == 0 for e in ui),
        "Controlled quit/relaunch journal differs",
    )
    require(
        dt.datetime.fromisoformat(reports["before-final"]["recorded_at_utc"])
        < dt.datetime.fromisoformat(ui[2]["started_at_utc"])
        < dt.datetime.fromisoformat(reports["stopped"]["started_at_utc"])
        < dt.datetime.fromisoformat(ui[4]["started_at_utc"])
        < dt.datetime.fromisoformat(reports["after-inspect"]["started_at_utc"]),
        "Restart witness boundary order differs",
    )
    host_exit = json.loads((directory / "after-stage-host-exit.json").read_text())
    require(
        host_exit["observed_tool_exit_code"] == HOST_EXIT_CODE
        and host_exit["complete_reports"] == COMPLETE_AFTER_EXIT,
        "Host exit observation was lost",
    )


def check_oracle_queries(directory: Path) -> None:
    """Check the inventory of the oracle queries and each query's code."""
    queries = list((directory / "oracle-queries").glob("*.json"))
    require(
        len(queries) == ORACLE_QUERIES
        and {p.stem.removeprefix("LA-D-") for p in queries} == ORACLE_ADDRESSES,
        "Live oracle inventory differs",
    )
    for path in queries:
        q = json.loads(path.read_text())
        require(
            q["program"]["sha256"] == ORACLE_SHA256
            and not q["result"].get("isError", False)
            and q["result"]["structuredContent"]["code"]
            == path.with_suffix(".c").read_text(),
            "Live oracle identity/code differs",
        )
