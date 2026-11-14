"""Fault controls for the finite Classic/native proxy baseline corpus."""

from __future__ import annotations

import copy
import json
import unittest
from pathlib import Path

from verify_classic_native_baseline import (
    equal_pairs,
    flow,
    verify,
    verify_control,
    verify_proxy_log,
    verify_watchdog,
)

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-14/classic-proxy-baseline-01"
)


def wire(report: dict, events: tuple[str, ...]) -> bytes:
    return b"".join(
        bytes.fromhex(e["raw_hex"]) for e in report["entries"] if e["event"] in events
    )


class ClassicNativeBaselineTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.reports = {
            case: json.loads((CORPUS / case / "proxy/report.json").read_text())
            for case in ("b46", "b47")
        }
        cls.client = {
            case: wire(r, ("client-handshake", "login-request", "client"))
            for case, r in cls.reports.items()
        }
        cls.server = {
            case: wire(r, ("server-handshake", "server"))
            for case, r in cls.reports.items()
        }
        cls.data = (
            wire(cls.reports["b47"], ("data-client",)),
            wire(cls.reports["b47"], ("data-server",)),
        )

    def test_portable_corpus(self) -> None:
        receipt = verify(CORPUS)
        self.assertEqual(receipt["b46"]["control"]["request_types"], [107])
        self.assertEqual(
            receipt["b47"]["control"]["request_types"], [107, 121, 300, 212]
        )
        self.assertEqual(receipt["b47"]["data_bytes"], [16, 58])

    def test_changed_reply_type(self) -> None:
        server = bytearray(self.server["b47"])
        server[10:12] = (1).to_bytes(2, "big")
        with self.assertRaisesRegex(ValueError, "Reply sequence"):
            verify_control("b47", self.client["b47"], bytes(server))

    def test_changed_reply_id(self) -> None:
        server = bytearray(self.server["b47"])
        server[12:16] = (9).to_bytes(4, "big")
        with self.assertRaisesRegex(ValueError, "Reply sequence"):
            verify_control("b47", self.client["b47"], bytes(server))

    def test_wrong_login_161(self) -> None:
        server = self.server["b47"].replace(
            bytes.fromhex("00a100020000"), bytes.fromhex("00a100020001"), 1
        )
        with self.assertRaisesRegex(ValueError, "Login ACK fields"):
            verify_control("b47", self.client["b47"], server)

    def test_changed_agreement(self) -> None:
        server = self.server["b47"].replace(
            b"This is the server agreement", b"That is the server agreement", 1
        )
        with self.assertRaisesRegex(ValueError, "Agreement text"):
            verify_control("b47", self.client["b47"], server)

    def test_b46_did_not_get_121(self) -> None:
        with self.assertRaisesRegex(ValueError, "Request sequence"):
            verify_control("b47", self.client["b46"], self.server["b47"])
        with self.assertRaisesRegex(ValueError, "Request sequence"):
            verify_control("b46", self.client["b47"], self.server["b46"])

    def test_changed_capture_view(self) -> None:
        pairs = [(self.client["b47"], self.server["b47"])] * 5
        pairs[2] = (self.client["b47"][:-1] + b"x", self.server["b47"])
        with self.assertRaisesRegex(ValueError, "Capture view byte mismatch"):
            equal_pairs(pairs, [150, 514])

    def test_missing_guest_syn(self) -> None:
        route = ["client-guest-post.pcap", "10.0.2.15", 49162, "10.0.2.2", 15652]
        with self.assertRaisesRegex(ValueError, "Missing or reused route SYN"):
            flow([], route)

    def test_late_relay_teardown(self) -> None:
        report = copy.deepcopy(self.reports["b47"])
        report["observation"]["relay_teardown_ns"] = (
            report["observation"]["ack_sent_monotonic_ns"] + 31_000_000_000
        )
        with self.assertRaisesRegex(ValueError, "Watchdog teardown"):
            verify_watchdog(report)

    def test_native_rejection_claim_and_bad_banner(self) -> None:
        report = copy.deepcopy(self.reports["b47"])
        report["status"] = "native-rejection"
        with self.assertRaisesRegex(ValueError, "Proxy outcome"):
            verify_watchdog(report)
        with self.assertRaisesRegex(ValueError, "Data server log"):
            verify_proxy_log(
                "b47",
                self.reports["b47"],
                self.client["b47"],
                self.server["b47"],
                (self.data[0], self.data[1][:-1] + b"x"),
            )


if __name__ == "__main__":
    unittest.main()
