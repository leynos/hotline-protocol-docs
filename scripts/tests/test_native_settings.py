"""Controls for bounded field-113 plans and observed notification semantics."""

import copy
import typing as typ

import pytest
from native_plan import packet, payload
from native_settings_cases import CASES, cases, pm_request
from protocol_capture import decode_frame, validate_plan
from verify_native_settings import semantic

type Frame = dict[str, typ.Any]

CASE_COUNT = 10
BARRIERS = [
    (41, "main"),
    (70, "main"),
    (71, "main"),
    (72, "subject"),
    (81, "main"),
    (82, "subject"),
]
HANDSHAKE_HEX = "54525450484f544c00010002"
PRIVATE_MESSAGE = 108
CLIENT_INFO = 304
ACCOUNT_REQUESTS = {350, 351, 352, 353}
SETTINGS_SENT = 2
RESTORE_FIELDS = [
    {"id": 102, "hex": b"settings25".hex()},
    {"id": 104, "hex": "0007"},
    {"id": 113, "hex": "0000"},
]


def frame(
    connection: str, kind: int, fields: list[tuple[int, bytes]], **options: int
) -> Frame:
    """Build a decoded frame as the capture report holds it.

    Parameters
    ----------
    connection : str
        The connection that received the frame.
    kind : int
        The transaction type.
    fields : list[tuple[int, bytes]]
        The fields of the frame.
    **options : int
        ``identifier`` (default 90) and ``reply`` (default 0).

    Returns
    -------
    dict[str, typing.Any]
        The decoded frame, with its connection and action.
    """
    identifier, reply = options.get("identifier", 90), options.get("reply", 0)
    decoded = decode_frame(
        bytes.fromhex(packet(kind, identifier, payload(fields), reply=reply))
    )
    return {"connection": connection, "action": 0, **decoded}


class SettingsPreparationTests:
    """Controls for bounded field-113 plans and observed notification semantics."""

    def test_ten_plans_validate_and_restore_without_account_mutation(self) -> None:
        """Every plan validates, sends one message and two settings, and restores."""
        assert len(CASES) == CASE_COUNT, "expected ten cases"
        for name, (steps, expected) in cases().items():
            validate_plan({
                "schema_version": 1,
                "profile": "native-mac-oracle",
                "operator": "test",
                "oracle_sha256": expected["oracle_sha256"],
                "gap_ids": ["GAP-015"],
                "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
                "steps": steps,
            })
            kinds = [
                decode_frame(bytes.fromhex(s["hex"].replace("{subject_uid}", "0002")))[
                    "type"
                ]
                for s in steps
                if s["op"] == "send" and s["hex"] != HANDSHAKE_HEX
            ]
            assert kinds.count(PRIVATE_MESSAGE) == 1, f"{name}: one message"
            assert kinds.count(CLIENT_INFO) == SETTINGS_SENT, f"{name}: two settings"
            assert not set(kinds) & ACCOUNT_REQUESTS, f"{name}: no account request"
            settings = [
                decode_frame(bytes.fromhex(step["hex"]))
                for step in steps
                if step["op"] == "send"
                and step["connection"] == "subject"
                and step["hex"] != HANDSHAKE_HEX
                and decode_frame(bytes.fromhex(step["hex"]))["type"] == CLIENT_INFO
            ]
            assert settings[-1]["fields"] == RESTORE_FIELDS, f"{name}: restore"

    def test_dynamic_uid_is_exact_two_byte_field(self) -> None:
        """The saved user id is substituted as a two-byte field 103."""
        step = pm_request(70, b"settings25-unique")
        raw = bytes.fromhex(step["hex"].replace("{subject_uid}", "0123"))
        assert decode_frame(raw)["fields"][0] == {"id": 103, "hex": "0123"}, "uid"

    def test_semantic_rejects_forged_refusal_as_zero_option(self) -> None:
        """A refusal without its feedback is not read as the zero option."""
        update = frame(
            "main", 301, [(103, b"\0\x12"), (102, b"settings25"), (104, b"\0\x07")]
        )
        report = {
            "frames": [
                copy.deepcopy(update),
                copy.deepcopy(update),
                copy.deepcopy(update),
                frame(
                    "subject",
                    104,
                    [(103, b"\0\x11"), (113, b"\0\x01"), (101, b"settings25-unique")],
                ),
                *[
                    frame(connection, 0, [], identifier=identifier, reply=1)
                    for identifier, connection in BARRIERS
                ],
            ]
        }
        expected = {
            "case": "absent",
            "expected_flags": 0,
            "pm_text": b"settings25-unique".hex(),
            "duplicate": False,
        }
        semantic(report, expected)
        bad = copy.deepcopy(report)
        bad["frames"] = [f for f in bad["frames"] if f["type"] != 104]
        with pytest.raises(ValueError, match="Suppression"):
            semantic(bad, expected)
