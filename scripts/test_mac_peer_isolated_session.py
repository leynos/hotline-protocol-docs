"""Semantic negative controls for the finite isolated Mac client corpus."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import read_packets
from verify_mac_peer_isolated_session import (
    check_control,
    check_data,
    check_dns_and_egress,
    check_observer,
    flow,
    syn,
    utc_us,
    verify,
)

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01"
)


def changed_capture(corpus: Path, name: str, before: bytes, after: bytes) -> None:
    path = corpus / name
    raw = path.read_bytes()
    if before not in raw:
        raise AssertionError("Negative-control bytes absent")
    path.write_bytes(raw.replace(before, after, 1))
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["capture"][name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


class IsolatedMacSessionTests(unittest.TestCase):
    def test_complete_bounded_session(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["status"], "verified-isolated-finite-session")
        self.assertEqual(result["control_bytes"], {"client": 150, "server": 514})
        self.assertEqual(result["data_bytes"], {"client": 16, "server": 58})
        self.assertEqual(result["control"]["uid"], 14)
        self.assertEqual(result["control"]["data_reference_hex"], "002e037f")
        self.assertEqual(result["dns"]["matched_unreachable"], 15)
        self.assertGreater(result["data_last_to_quiet_end_us"], 130_000_000)
        self.assertFalse(result["banner_ui_complete"])

    def test_guest_control_byte_mismatch_rejected_after_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(shutil.copytree(CORPUS, Path(temporary) / "corpus"))
            changed_capture(corpus, "client-guest-final.pcap", b"TRTPHOTL", b"TRTPHOXX")
            with self.assertRaisesRegex(ValueError, "Control bytes differ across NAT"):
                verify(corpus)

    def test_wrong_161_rejected(self) -> None:
        packets = read_packets(CORPUS / "host-final.pcap")
        control_syn = syn(packets, "127.0.0.1", "127.0.0.1", 15500)
        _, client, server = flow(packets, control_syn)
        old = b"\x00\xa1\x00\x02\x00\x00"
        self.assertIn(old, server)
        changed = server.replace(old, b"\x00\xa1\x00\x02\x00\x01", 1)
        with self.assertRaisesRegex(ValueError, "Login 161"):
            check_control(client, changed)

    def test_dynamic_ref_must_match_data_header(self) -> None:
        packets = read_packets(CORPUS / "host-final.pcap")
        data_syn = syn(packets, "127.0.0.1", "127.0.0.1", 15501)
        _, sent, received = flow(packets, data_syn)
        check_data(bytes.fromhex("002e037f"), sent, received)
        with self.assertRaisesRegex(ValueError, "Dynamic 212/data"):
            check_data(bytes.fromhex("002e037e"), sent, received)

    def test_changed_dns_error_rejected_from_packet_bytes(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / "guest.pcap"
            raw = (CORPUS / "client-guest-final.pcap").read_bytes()
            marker = b"\x03\x00\xb9\x29"
            self.assertIn(marker, raw)
            changed.write_bytes(raw.replace(marker, b"\x03\x01\xb9\x29", 1))
            with self.assertRaisesRegex(ValueError, "DNS error type/code"):
                check_dns_and_egress(changed, utc_us(CORPUS / "disconnect-time.txt"))

    def test_unexpected_host_observer_record_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            changed = Path(temporary) / "observer.pcap"
            changed.write_bytes(
                (CORPUS / "nonlocal-known-ip.pcap").read_bytes() + b"\x00" * 16
            )
            with self.assertRaisesRegex(ValueError, "Unexpected public-IP"):
                check_observer(changed)

    def test_shortened_observation_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = Path(shutil.copytree(CORPUS, Path(temporary) / "corpus"))
            (corpus / "quiet-end-time.txt").write_text("2026-11-13 19:58:00 UTC\n")
            with self.assertRaisesRegex(ValueError, "Finite quiet window"):
                verify(corpus)


if __name__ == "__main__":
    unittest.main()
