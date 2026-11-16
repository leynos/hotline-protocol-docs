"""Provenance checks of the bounded 303 diagnostic reports.

Each helper runs one phase of the original check chain, in the original order, so
the first failing check and its message do not change. The entry point is
``semantic``, which verify_native_diagnostics re-exports.
"""

import native_diagnostic_cases as cases
from native_auth_cases import complement
from native_wire_names import (
    FIELD_ACCESS_BITMAP,
    FIELD_DATA,
    FIELD_LOGIN,
    FIELD_NAME,
    FIELD_PASSWORD,
    FIELD_USER_ID,
    TYPE_PRESENCE_UPDATE,
    TYPE_PRIVILEGES_NOTIFICATION,
)
from verify_native_account_updates import enumeration
from verify_native_auth import reply, roster, selected
from verify_native_core import require
from verify_native_diagnostic_frames import (
    DENIED,
    DIAGNOSTIC_TYPE,
    MISSING,
    NAMES,
    UID_BYTES,
    failure,
    sent,
    success,
    uid_field,
)
from verify_native_shx import fields

FIXTURE_NAME = b"framing-fixture"  # the account name that the rosters must list
ACCOUNT_COUNT = 2  # accounts in the preflight inventory
CURRENT_ROSTER_ROWS = 2  # one row for the owned subject, one for the administrator
MISSING_UID = b"\xff\xff"  # the UID that names no session


def _check_preflight(preflight: dict) -> tuple[list, list]:
    """Check the preflight inventory, the absent owned account and the roster.

    Parameters
    ----------
    preflight : dict
        The verified preflight report.

    Returns
    -------
    tuple[list, list]
        The account inventory and the administrator roster before the seed.
    """
    baseline = enumeration(reply(preflight, 10))
    require(len(baseline) == ACCOUNT_COUNT, "Preflight account inventory differs")
    require(reply(preflight, 11)["error"] == 1, "Owned account existed before seed")
    first_roster = roster(reply(preflight, 12))
    require(
        len(first_roster) == 1 and first_roster[0]["name_hex"] == FIXTURE_NAME.hex(),
        "Preflight admin roster ambiguous",
    )
    return baseline, first_roster


def _check_seed(seed: dict) -> None:
    """Check that the seed created the owned zero-access account.

    Parameters
    ----------
    seed : dict
        The verified seed report.
    """
    require(
        reply(seed, 10)["error"] == 0
        and fields(reply(seed, 11))
        == {
            FIELD_NAME: cases.NAME,
            FIELD_LOGIN: complement(cases.KEY),
            FIELD_PASSWORD: b"x",
            FIELD_ACCESS_BITMAP: cases.ACCESS,
        },
        "Owned zero-access account seed differs",
    )


def _check_zero_privilege(observe: dict) -> None:
    """Check the effective privilege that the zero-access subject received.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    """
    require(
        fields(
            next(
                f
                for f in selected(observe, "zero")
                if f["type"] == TYPE_PRIVILEGES_NOTIFICATION
            )
        )
        == {FIELD_ACCESS_BITMAP: cases.ACCESS},
        "Subject effective privilege differs",
    )


def _subject_uid(observe: dict) -> bytes:
    """Return the UID of the owned subject from its join notification.

    Parameters
    ----------
    observe : dict
        The verified observation report.

    Returns
    -------
    bytes
        The two-byte UID of the owned subject.
    """
    joined = [
        fields(f)
        for f in selected(observe, "main")
        if f["type"] == TYPE_PRESENCE_UPDATE and not f["is_reply"]
    ]
    require(
        len(joined) == 1 and joined[0].get(FIELD_NAME) == cases.NAME,
        "Owned subject notification ambiguous",
    )
    target = joined[0][FIELD_USER_ID]
    require(len(target) == UID_BYTES, "Owned subject UID width differs")
    return target


def _current_admin_uid(observe: dict, target: bytes) -> int:
    """Check the current roster and return the administrator's UID.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    target : bytes
        The two-byte UID of the owned subject.

    Returns
    -------
    int
        The UID of the row that is not the owned subject.
    """
    current = roster(reply(observe, 20))
    require(
        len(current) == CURRENT_ROSTER_ROWS
        and sum(row["name_hex"] == cases.NAME.hex() for row in current) == 1
        and any(row["uid"] == int.from_bytes(target, "big") for row in current),
        "Current owned subject identity differs",
    )
    return next(row["uid"] for row in current if row["name_hex"] != cases.NAME.hex())


def _check_reply_order(observe: dict) -> None:
    """Check the order of the diagnostic replies in the observation.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    """
    ordered = [
        (frame["connection"], frame["id"])
        for frame in observe["frames"]
        if frame["type"] == 0
        and frame["is_reply"]
        and frame["id"] in {10, 11, 12, 13, 20}
    ]
    require(
        ordered
        == [("main", 10), ("zero", 11), ("main", 12), ("main", 13), ("main", 20)],
        "Diagnostic reply order differs",
    )


def _check_targeted(observe: dict, target: bytes) -> None:
    """Check the allowed and the denied 303 requests aimed at the subject.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    target : bytes
        The two-byte UID of the owned subject.
    """
    require(
        uid_field(sent(observe, DIAGNOSTIC_TYPE, 10)) == target,
        "Allowed 303 targeted another session",
    )
    success(reply(observe, 10), cases.NAME, cases.NAME, cases.KEY)
    require(
        uid_field(sent(observe, DIAGNOSTIC_TYPE, 11, "zero")) == target,
        "Denied target differs",
    )
    failure(reply(observe, 11, "zero"), DENIED)


def _check_missing_control(observe: dict) -> None:
    """Check the 303 request that names no session.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    """
    require(
        uid_field(sent(observe, DIAGNOSTIC_TYPE, 12)) == MISSING_UID,
        "Missing UID control differs",
    )
    failure(reply(observe, 12), MISSING)


def _check_stale(observe: dict, first_roster: list, current_admin: int) -> bytes:
    """Check that the prior-session UID was not relabelled as current.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    first_roster : list
        The administrator roster read before the seed.
    current_admin : int
        The UID of the current administrator row.

    Returns
    -------
    bytes
        The two-byte prior-session UID.
    """
    stale = uid_field(sent(observe, DIAGNOSTIC_TYPE, 13))
    require(
        stale == first_roster[0]["uid"].to_bytes(UID_BYTES, "big")
        and stale != current_admin.to_bytes(UID_BYTES, "big"),
        "Prior-session UID was relabelled current",
    )
    failure(reply(observe, 13), MISSING)
    return stale


def _check_observe(observe: dict, first_roster: list) -> dict:
    """Check the observation report and collect the subject identities.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    first_roster : list
        The administrator roster read before the seed.

    Returns
    -------
    dict
        The subject UID ``target``, the administrator UID ``current_admin`` and the
        prior-session UID ``stale``.
    """
    target = _subject_uid(observe)
    current_admin = _current_admin_uid(observe, target)
    _check_reply_order(observe)
    _check_targeted(observe, target)
    _check_missing_control(observe)
    stale = _check_stale(observe, first_roster, current_admin)
    return {"target": target, "current_admin": current_admin, "stale": stale}


def _check_self(self_report: dict) -> bytes:
    """Check the same-connection self lookup and its own 303 request.

    Parameters
    ----------
    self_report : dict
        The verified self report.

    Returns
    -------
    bytes
        The two-byte UID of the same-connection session.
    """
    own_rows = roster(reply(self_report, 10))
    require(
        len(own_rows) == 1 and own_rows[0]["name_hex"] == FIXTURE_NAME.hex(),
        "Same-connection self roster ambiguous",
    )
    own_uid = own_rows[0]["uid"].to_bytes(UID_BYTES, "big")
    require(
        uid_field(sent(self_report, DIAGNOSTIC_TYPE, 11)) == own_uid,
        "Self 303 UID differs",
    )
    success(reply(self_report, 11), FIXTURE_NAME, b"administrator", b"admin")
    return own_uid


def _check_cleanup(cleanup: dict, baseline: list) -> None:
    """Check that the owned account was removed and the baseline restored.

    Parameters
    ----------
    cleanup : dict
        The verified cleanup report.
    baseline : list
        The account inventory read before the seed.
    """
    require(
        reply(cleanup, 10)["error"] == 0
        and reply(cleanup, 11)["error"] == 1
        and enumeration(reply(cleanup, 12)) == baseline,
        "Owned account cleanup/baseline differs",
    )


def _summary(observe: dict, self_report: dict, subject: dict, own_uid: bytes) -> dict:
    """Assemble the identities and text lengths that the checks establish.

    Parameters
    ----------
    observe : dict
        The verified observation report.
    self_report : dict
        The verified self report.
    subject : dict
        The identities returned by ``_check_observe``.
    own_uid : bytes
        The two-byte UID of the same-connection session.

    Returns
    -------
    dict
        The summary, with its keys in the order that the verifier prints them.
    """
    return {
        "subject_uid_hex": subject["target"].hex(),
        "current_admin_uid_hex": subject["current_admin"]
        .to_bytes(UID_BYTES, "big")
        .hex(),
        "stale_uid_hex": subject["stale"].hex(),
        "self_uid_hex": own_uid.hex(),
        "subject_text_bytes": len(fields(reply(observe, 10))[FIELD_DATA]),
        "self_text_bytes": len(fields(reply(self_report, 11))[FIELD_DATA]),
    }


def semantic(reports: dict[str, dict]) -> dict:
    """Check provenance-sensitive 303 meanings independently of file hashes.

    Parameters
    ----------
    reports : dict[str, dict]
        The verified report of each diagnostic case, keyed by case name.

    Returns
    -------
    dict
        The identities and text lengths that the checks establish.
    """
    preflight, seed, observe, self_report, cleanup = (reports[name] for name in NAMES)
    baseline, first_roster = _check_preflight(preflight)
    _check_seed(seed)
    _check_zero_privilege(observe)
    subject = _check_observe(observe, first_roster)
    own_uid = _check_self(self_report)
    _check_cleanup(cleanup, baseline)
    return _summary(observe, self_report, subject, own_uid)
