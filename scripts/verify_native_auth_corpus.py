"""Verify the captures, exploratory runs and oracle records of an auth corpus."""

import dataclasses as dc
import json
import typing as typ

from capture_acceptance import driver_is
from native_auth_steps import FIRST_ID, PAIR_OFFSET
from native_packet_evidence import reconcile
from native_wire_names import (
    ACCESS_BITMAP_BYTES,
    FIELD_ACCESS_BITMAP,
    FIELD_PASSWORD,
    FIELD_USER_ID,
    LOGIN_TABLE_ADDRESS,
    LOGIN_TABLE_BYTES,
    TYPE_USER_LEFT,
)
from protocol_capture import ORACLE_SHA256, decode_frame, verify_capture
from verify_native_auth_checks import check_lookup, check_state
from verify_native_auth_frames import reply, roster
from verify_native_banners import fields
from verify_native_core import require
from verify_native_framing import check_quiet

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

STATE_KINDS = {
    "login-state",
    "preauth-acceptance",
    "failed-password-acceptance",
    "reauthentication",
}
INITIAL_CASES = {"login-after-premature-acceptance", "repeated-login-before-acceptance"}
GUEST_ABSENT_ID = 9
OWNED_IDS = range(FIRST_ID, FIRST_ID + 5)  # the five accounts that the plan makes
LONG_NAME_ID = 13  # the 32-byte key that the native file system refuses
QUERY_COUNT = 14
LOGIN_NORMALIZATION_QUERY = "AU-M-login-normalization"
LATE_DEPARTURE_ROSTER = 13  # the roster that the observer reads last
# Entries of the normalization table: NUL stays, CR stays, A-Z becomes a-z and
# the high byte 0x80 becomes 0x8a (the plan names these cases).
TABLE_CR = 13
TABLE_UPPER = slice(65, 91)
TABLE_LOWER = bytes(range(97, 123))
TABLE_HIGH_BYTE = 128
TABLE_HIGH_BYTE_TARGET = 138


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """What an authentication corpus holds besides its transcripts.

    Attributes
    ----------
    directory : pathlib.Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The corpus manifest.
    host : list[dict[str, typing.Any]]
        The host packet capture.
    guest : list[dict[str, typing.Any]]
        The guest packet capture.
    driver : str
        The hash of the capture driver as it ran.
    agreement : bytes
        The configured agreement text.
    """

    directory: Path
    manifest: Report
    host: list[Report]
    guest: list[Report]
    driver: str
    agreement: bytes


def unread(corpus: Corpus, key: str) -> dict[str, bytes]:
    """Return the output that the capture left unread on each connection.

    Returns
    -------
    dict[str, bytes]
        The unread bytes by connection name.
    """
    recorded = corpus.manifest["unread_output"].get(key, {})
    return {k: bytes.fromhex(v) for k, v in recorded.items()}


def check_capture(
    corpus: Corpus, name: str, case: tuple[list[Report], Report]
) -> tuple[Report, Report]:
    """Check one transcript against its plan and reconcile it with the packets.

    Returns
    -------
    tuple[dict[str, typing.Any], dict[str, typing.Any]]
        The verified report and its packet reconciliation.
    """
    steps, expectation = case
    path = corpus.directory / "transcripts" / name
    plan = json.loads((path / "plan.json").read_text())
    require(
        plan["steps"] == steps and plan["expectation"] == expectation,
        "Auth plan differs",
    )
    report = verify_capture(path)
    require(
        report["status"] == "completed" and driver_is(report, corpus.driver),
        "Auth capture status/source differs",
    )
    for connection, stream in report["streams"].items():
        require(
            stream["sent_hex"]
            == "".join(
                step["hex"]
                for step in steps
                if step["op"] == "send" and step["connection"] == connection
            ),
            "Physical auth input differs",
        )
    packets = reconcile(report, corpus.host, corpus.guest, unread(corpus, name))
    check_quiet(report, plan)
    return report, packets


def check_seed(report: Report) -> None:
    """Check that the original guest was absent and the owned accounts were made."""
    require(
        reply(report, GUEST_ABSENT_ID)["error"] == 1, "Original guest was not absent"
    )
    for identifier in OWNED_IDS:
        refused = 1 if identifier == LONG_NAME_ID else 0
        require(
            reply(report, identifier)["error"] == refused
            and reply(report, identifier + PAIR_OFFSET)["error"] == refused,
            "Native account length/setup outcomes differ",
        )


def check_guest_create(report: Report) -> None:
    """Check that the temporary guest was created with no privileges or password."""
    first = reply(report, FIRST_ID)
    created = reply(report, FIRST_ID + 1)
    require(
        first["error"] == created["error"] == 0
        and fields(created)[FIELD_ACCESS_BITMAP] == bytes(ACCESS_BITMAP_BYTES)
        and FIELD_PASSWORD not in fields(created),
        "Temporary guest control differs",
    )


def check_cleanup(report: Report) -> None:
    """Check that every owned account was deleted and then read back as absent."""
    require(
        all(
            reply(report, i)["error"] == 0
            and reply(report, i + PAIR_OFFSET)["error"] == 1
            for i in OWNED_IDS
        ),
        "Owned account cleanup not verified",
    )


def check_outcome(
    name: str, report: Report, case: tuple[list[Report], Report], agreement: bytes
) -> Report | None:
    """Check what a capture observed, according to the kind of its case.

    Returns
    -------
    dict[str, typing.Any] | None
        The state observation of a login-state kind of case; otherwise ``None``.
    """
    expectation = case[1]
    kind = expectation["kind"]
    if kind == "lookup":
        check_lookup(report, expectation, agreement)
    elif kind in STATE_KINDS:
        return check_state(name, report, expectation, agreement)
    elif kind == "account-seed":
        check_seed(report)
    elif kind == "guest-create":
        check_guest_create(report)
    elif kind == "account-cleanup":
        check_cleanup(report)
    return None


def check_initial_cases(corpus: Corpus, packets: dict[str, Report]) -> None:
    """Check the two retained exploratory captures, adding their reconciliations."""
    manifest = corpus.manifest
    require(
        set(manifest["initial_cases"]) == INITIAL_CASES,
        "Exploratory auth inventory differs",
    )
    for name in manifest["initial_cases"]:
        key = "initial/" + name
        report = verify_capture(corpus.directory / "initial" / name)
        require(
            report["status"]
            == (
                "failed" if name == "login-after-premature-acceptance" else "completed"
            ),
            "Initial recovery/overlap outcome differs",
        )
        packets[key] = reconcile(report, corpus.host, corpus.guest, unread(corpus, key))


def check_late_departure(corpus: Corpus, reports: dict[str, Report]) -> None:
    """Check that the unread departure is that of the subject, still listed."""
    tail = bytes.fromhex(
        corpus.manifest["unread_output"]["repeated-login-before-acceptance"]["observer"]
    )
    note = decode_frame(tail)
    require(
        note["type"] == TYPE_USER_LEFT and note["is_reply"] == 0,
        "Unread delayed departure differs",
    )
    uid = int.from_bytes(fields(note)[FIELD_USER_ID], "big")
    final_roster = roster(
        reply(
            reports["repeated-login-before-acceptance"],
            LATE_DEPARTURE_ROSTER,
            "observer",
        )
    )
    require(
        uid in {r["uid"] for r in final_roster},
        "Late departure was not the still-listed subject",
    )


def check_table(data: Report) -> None:
    """Check the retained login normalization table."""
    table = bytes.fromhex(data["hex"])
    require(
        data["address"] == LOGIN_TABLE_ADDRESS
        and len(table) == LOGIN_TABLE_BYTES
        and table[0] == 0
        and table[TABLE_CR] == TABLE_CR
        and table[TABLE_UPPER] == TABLE_LOWER
        and table[TABLE_HIGH_BYTE] == TABLE_HIGH_BYTE_TARGET,
        "Native login normalization table differs",
    )


def check_oracle(directory: Path) -> None:
    """Check every retained oracle query against the oracle program."""
    queries = json.loads((directory / "oracle-plan.json").read_text())
    require(
        len(queries) == QUERY_COUNT and len({q["id"] for q in queries}) == QUERY_COUNT,
        "Auth query inventory differs",
    )
    for query in queries:
        record = json.loads(
            (directory / "oracle-queries" / (query["id"] + ".json")).read_text()
        )
        require(
            record["query"] == query
            and record["program"]["sha256"] == ORACLE_SHA256
            and not record["result"]["isError"],
            "Auth query identity/outcome differs",
        )
        data = record["result"]["structuredContent"]
        if "code" in data:
            require(
                data["code"]
                == (directory / "oracle-queries" / (query["id"] + ".c")).read_text(),
                "Auth oracle source differs",
            )
        if query["id"] == LOGIN_NORMALIZATION_QUERY:
            check_table(data)
