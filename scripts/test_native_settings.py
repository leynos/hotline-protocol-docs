"""Controls for bounded field-113 plans and observed notification semantics."""

import copy
import unittest

from native_settings_cases import CASES, cases, pm_request
from protocol_capture import decode_frame, validate_plan
from verify_native_settings import semantic


def frame(
    connection: str,
    kind: int,
    fields: list[tuple[int, bytes]],
    *,
    identifier: int = 90,
    reply: int = 0,
) -> dict:
    from native_plan import packet, payload

    decoded = decode_frame(
        bytes.fromhex(packet(kind, identifier, payload(fields), reply=reply))
    )
    return {"connection": connection, "action": 0, **decoded}


class SettingsPreparationTests(unittest.TestCase):
    def test_ten_plans_validate_and_restore_without_account_mutation(self) -> None:
        self.assertEqual(len(CASES), 10)
        for name, (steps, expected) in cases().items():
            with self.subTest(name=name):
                validate_plan(
                    {
                        "schema_version": 1,
                        "profile": "native-mac-oracle",
                        "operator": "test",
                        "oracle_sha256": expected["oracle_sha256"],
                        "gap_ids": ["GAP-015"],
                        "endpoints": {"control": {"host": "127.0.0.1", "port": 15500}},
                        "steps": steps,
                    }
                )
                kinds = [
                    decode_frame(
                        bytes.fromhex(s["hex"].replace("{subject_uid}", "0002"))
                    )["type"]
                    for s in steps
                    if s["op"] == "send" and s["hex"] != "54525450484f544c00010002"
                ]
                self.assertEqual(kinds.count(108), 1)
                self.assertEqual(kinds.count(304), 2)
                self.assertFalse(set(kinds) & {350, 351, 352, 353})
                settings = [
                    decode_frame(bytes.fromhex(step["hex"]))
                    for step in steps
                    if step["op"] == "send"
                    and step["connection"] == "subject"
                    and step["hex"] != "54525450484f544c00010002"
                    and decode_frame(bytes.fromhex(step["hex"]))["type"] == 304
                ]
                self.assertEqual(
                    settings[-1]["fields"],
                    [
                        {"id": 102, "hex": b"settings25".hex()},
                        {"id": 104, "hex": "0007"},
                        {"id": 113, "hex": "0000"},
                    ],
                )

    def test_dynamic_uid_is_exact_two_byte_field(self) -> None:
        raw = bytes.fromhex(
            pm_request(70, b"settings25-unique")["hex"].replace("{subject_uid}", "0123")
        )
        self.assertEqual(decode_frame(raw)["fields"][0], {"id": 103, "hex": "0123"})

    def test_semantic_rejects_forged_refusal_as_zero_option(self) -> None:
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
                    for identifier, connection in [
                        (41, "main"),
                        (70, "main"),
                        (71, "main"),
                        (72, "subject"),
                        (81, "main"),
                        (82, "subject"),
                    ]
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
        with self.assertRaisesRegex(ValueError, "Suppression"):
            semantic(bad, expected)


if __name__ == "__main__":
    unittest.main()
