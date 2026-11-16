"""Provenance checks of the failed 303 load attempt and its owned-file cleanup.

Each helper runs one phase of the original check chain, in the original order, so
the first failing check and its message do not change. The entry point is
``semantic``, which verify_native_diagnostic_load re-exports.
"""

import json

from native_diagnostic_load_cases import NAME
from native_wire_names import (
    FIELD_DATA,
    FIELD_FILE_NAME,
    FIELD_NAME,
    FIELD_TRANSFER_REFERENCE,
    TYPE_DELETE_FILE,
)
from verify_native_account_updates import enumeration
from verify_native_core import require
from verify_native_diagnostic_load_frames import (
    CASES,
    FIXTURE_NAME,
    current_uid,
    reply,
    sent,
)
from verify_native_mkdir import listing
from verify_native_shx import fields

PREFLIGHT_ACTIONS = 18  # the actions that the completed preflight performs
SEED_FAILED_ACTIONS = 11  # the actions that the seed completes before its reset
CLEANUP_ACTIONS = 24  # the actions that the completed cleanup performs
ACCOUNT_COUNT = 2  # the accounts in the preflight inventory
TRANSFER_REFERENCE_BYTES = 4  # a transfer reference is four bytes
PARTIAL_STATUS_FIELD = 205  # the field that holds the status text of the partial file
UNREACHED_SEED_REPLY = 11  # the file-info reply that a failed seed must not produce


def _check_outcomes(preflight: dict, seed: dict, cleanup: dict) -> None:
    """Check the status and the action counts of the three cases.

    Parameters
    ----------
    preflight : dict
        The verified preflight report.
    seed : dict
        The verified seed report.
    cleanup : dict
        The verified cleanup report.
    """
    require(
        preflight["status"] == "completed"
        and preflight["completed_actions"] == PREFLIGHT_ACTIONS,
        "Preflight incomplete",
    )
    require(
        seed["status"] == "failed"
        and seed["completed_actions"] == SEED_FAILED_ACTIONS
        and seed["error"]
        == "ConnectionResetError: [Errno 104] Connection reset by peer",
        "Seed failure changed or was relabelled success",
    )
    require(
        cleanup["status"] == "completed"
        and cleanup["completed_actions"] == CLEANUP_ACTIONS
        and cleanup.get("branch") == "present",
        "Conditional cleanup did not complete its positive branch",
    )


def _check_preflight(preflight: dict) -> tuple[list, dict[bytes, bytes], str, dict]:
    """Check the preflight inventory, files and idle 303 reply.

    Parameters
    ----------
    preflight : dict
        The verified preflight report.

    Returns
    -------
    tuple[list, dict[bytes, bytes], str, dict]
        The account inventory, the Files listing, the same-session UID and the idle
        303 fields.
    """
    accounts = enumeration(reply(preflight, 10))
    require(len(accounts) == ACCOUNT_COUNT, "Original account count differs")
    files = listing(reply(preflight, 11))
    require(NAME not in files, "Owned file existed before seed")
    require(reply(preflight, 12)["error"] == 1, "Owned preflight 206 was not absent")
    uid = current_uid(preflight, 14, 15)
    idle = fields(reply(preflight, 15))
    require(
        reply(preflight, 15)["error"] == 0
        and set(idle) == {FIELD_DATA, FIELD_NAME}
        and idle[FIELD_NAME] == FIXTURE_NAME
        and NAME not in idle[FIELD_DATA],
        "Preflight idle 303 differs",
    )
    return accounts, files, uid, idle


def _check_seed(seed: dict) -> None:
    """Check the seed reference and that a failed seed produced no file-info reply.

    Parameters
    ----------
    seed : dict
        The verified seed report.
    """
    require(
        reply(seed, 10)["error"] == 0
        and len(fields(reply(seed, 10))[FIELD_TRANSFER_REFERENCE])
        == TRANSFER_REFERENCE_BYTES,
        "Seed 203 reference was not accepted",
    )
    require(
        not any(
            f["is_reply"] == 1 and f["id"] == UNREACHED_SEED_REPLY
            for f in seed["frames"]
        ),
        "Failed seed was incorrectly treated as file-info verified",
    )


def _check_partial(cleanup: dict, files: dict[bytes, bytes]) -> dict:
    """Check the partial file, which must be the one entry added to the Files view.

    Parameters
    ----------
    cleanup : dict
        The verified cleanup report.
    files : dict[bytes, bytes]
        The Files listing read before the seed.

    Returns
    -------
    dict
        The fields of the partial file's information reply.
    """
    info = reply(cleanup, 10)
    initial = fields(info)
    require(
        info["error"] == 0
        and initial[FIELD_FILE_NAME] == NAME
        and initial[PARTIAL_STATUS_FIELD] == b"Incomplete File",
        "Owned partial file identity/status differs",
    )
    listed = listing(reply(cleanup, 11))
    require(
        NAME in listed and set(listed) == set(files) | {NAME},
        "Partial file is not the sole added Files entry",
    )
    return initial


def _check_deletion(cleanup: dict, files: dict[bytes, bytes], accounts: list) -> None:
    """Check the guarded deletion and the restored Files and account views.

    Parameters
    ----------
    cleanup : dict
        The verified cleanup report.
    files : dict[bytes, bytes]
        The Files listing read before the seed.
    accounts : list
        The account inventory read before the seed.
    """
    require(
        fields(sent(cleanup, TYPE_DELETE_FILE, 17)) == {FIELD_FILE_NAME: NAME}
        and reply(cleanup, 17)["error"] == 0,
        "204 deleted another path or failed",
    )
    require(reply(cleanup, 12)["error"] == 1, "Owned file remains after 204")
    require(
        listing(reply(cleanup, 13)) == files,
        "Full Files view was not restored",
    )
    require(
        enumeration(reply(cleanup, 14)) == accounts,
        "Original account enumeration was not restored",
    )


def _check_idle_restored(cleanup: dict, idle: dict) -> str:
    """Check that the idle 303 reply was restored and return the cleanup UID.

    Parameters
    ----------
    cleanup : dict
        The verified cleanup report.
    idle : dict
        The idle 303 fields read in preflight.

    Returns
    -------
    str
        The same-session UID of the cleanup, as hexadecimal text.
    """
    uid = current_uid(cleanup, 15, 16)
    restored = fields(reply(cleanup, 16))
    require(
        reply(cleanup, 16)["error"] == 0 and restored == idle,
        "Idle 303 was not restored",
    )
    return uid


def _check_plan(cleanup: dict) -> None:
    """Check that the selected plan shows one guarded deletion.

    Parameters
    ----------
    cleanup : dict
        The verified cleanup report, which names its plan path.
    """
    plan = json.loads(cleanup["_plan_path"].read_text())
    deletes = [
        step
        for step in plan["steps"]
        if step["op"] == "send"
        and step["connection"] == "a"
        and step["hex"].startswith("000000cc")
    ]
    require(
        plan["expectation"]["branch"] == "present" and len(deletes) == 1,
        "Selected plan does not show one guarded deletion",
    )


def semantic(reports: dict[str, dict]) -> dict:
    """Check the provenance-sensitive meanings of the load attempt.

    Parameters
    ----------
    reports : dict[str, dict]
        The verified report of each case, keyed by case name.

    Returns
    -------
    dict
        The identities and counts that the checks establish.
    """
    preflight, seed, cleanup = (reports[name] for name in CASES)
    _check_outcomes(preflight, seed, cleanup)
    accounts, files, preflight_uid, idle = _check_preflight(preflight)
    _check_seed(seed)
    initial = _check_partial(cleanup, files)
    _check_deletion(cleanup, files, accounts)
    cleanup_uid = _check_idle_restored(cleanup, idle)
    _check_plan(cleanup)
    return {
        "preflight_uid": preflight_uid,
        "cleanup_uid": cleanup_uid,
        "baseline_file_entries": len(files),
        "partial_info_fields": {str(k): v.hex() for k, v in initial.items()},
        "seed_error": seed["error"],
    }
