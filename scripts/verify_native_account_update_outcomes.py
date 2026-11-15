"""Check the outcome of each account case: replies, login privileges and restoration."""

import typing as typ

from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_ERROR_TEXT,
    TYPE_LOGIN_AGREEMENT,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_account_update_checks import (
    ACCESS,
    LABELS,
    account_reply,
    enumeration,
    username,
    values,
)
from verify_native_auth import reply
from verify_native_core import require
from verify_native_mkdir import listing
from verify_native_shx import fields

type Report = dict[str, typ.Any]

COMPLETED_REPORTS = 31
PAIRED_CONNECTIONS = 34
INITIAL_ACCOUNT_COUNT = 2
INITIAL_FILE_COUNT = 41
# A login reply's frames: the ACK, the privileges, the agreement and the ACK.
LOGIN_FRAME_SHAPE = [
    (0, 0),
    (TYPE_PRIVILEGES_NOTIFICATION, 0),
    (TYPE_LOGIN_AGREEMENT, 0),
    (0, 0),
]


def check_label(reports: dict[str, Report], index: int, label: str) -> None:
    """Check the creation, update and retrieval replies of the account of ``label``."""
    pre = reply(reports["preflight"], index)
    require(
        pre["error"] == 1
        and fields(pre)
        == {
            FIELD_ERROR_TEXT: b"No account with login \xd2" + username(label) + b"\xd3."
        },
        "Owned account was not initially absent",
    )
    require(
        reply(reports["seed"], index)["error"] == 0
        and fields(reply(reports["seed"], index)) == {},
        "Account creation ACK differs",
    )
    account_reply(reply(reports["seed"], index + 100), label, after=False)
    changed = reports["mutation-" + label]
    account_reply(reply(changed, 10), label, after=False)
    require(
        reply(changed, 11)["error"] == 0 and fields(reply(changed, 11)) == {},
        "Account update ACK differs",
    )
    account_reply(reply(changed, 12), label, after=True)
    require(
        reply(changed, 90)["error"] == 0 and fields(reply(changed, 90)) == {},
        "Account update lost control liveness",
    )
    account_reply(reply(reports["final"], index), label, after=True)


def check_labels(reports: dict[str, Report]) -> None:
    """Check the replies of every owned account, in case order."""
    for index, label in enumerate(LABELS, 100):
        check_label(reports, index, label)


def check_login(key: str, report: Report) -> None:
    """Check that a login with the replacement password gets its privileges."""
    label = "preserve32" if key == "base32-login" else key.removeprefix("login-")
    access = ACCESS if key == "base32-login" else values(label, after=True)[3]
    require(
        [(f["type"], f["error"]) for f in report["frames"]] == LOGIN_FRAME_SHAPE
        and fields(report["frames"][1]) == {FIELD_ACCESS_BITMAP: access},
        "Replacement password login/privileges differ",
    )


def check_outcome(key: str, report: Report) -> None:
    """Check the outcome of one case from its name and its frames."""
    if key.startswith("login-") or key == "base32-login":
        check_login(key, report)
    elif key.startswith("reject-"):
        require(
            len(report["frames"]) == 1
            and reply(report, 1)["error"] == 1
            and fields(reply(report, 1)) == {FIELD_ERROR_TEXT: b"Incorrect login."},
            "Old/wrong password rejection differs",
        )
    elif key != "preflight":
        require(
            all(f["error"] == 0 for f in report["frames"]),
            "Account control operation failed",
        )


def check_outcomes(reports: dict[str, Report]) -> None:
    """Check the outcome of every case, in capture order."""
    for key, report in reports.items():
        check_outcome(key, report)


def check_restoration(reports: dict[str, Report]) -> None:
    """Check that the cleanup cases restored the account and Files inventories."""
    baseline = enumeration(reply(reports["preflight"], 10))
    files = listing(reply(reports["preflight"], 11))
    require(
        len(baseline) == INITIAL_ACCOUNT_COUNT and len(files) == INITIAL_FILE_COUNT,
        "Initial account/Files inventory differs",
    )
    for key in ["cleanup", "publish", "remove-publisher"]:
        require(
            enumeration(reply(reports[key], 90)) == baseline,
            "Owned account cleanup did not restore enumeration",
        )
        after = listing(reply(reports[key], 91))
        if key == "publish":
            require(b"m-au26-publish" in after, "Account publisher missing")
            after.pop(b"m-au26-publish")
        require(after == files, "Account helper cleanup did not restore Files")


def check_totals(
    reports: dict[str, Report], manifest: Report, connections: int
) -> None:
    """Check the report and connection totals against the manifest."""
    require(
        len(reports) == manifest["completed_reports"] == COMPLETED_REPORTS
        and connections == manifest["paired_connections"] == PAIRED_CONNECTIONS,
        "Account aggregate counts differ",
    )
