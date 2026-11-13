"""Negative controls for the bounded Classic client session verifier."""

import hashlib
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import read_packets
from verify_mac_peer_first_session import (
    CONTROL_CONNECT_US,
    HOST_CLIENT,
    HOST_SERVER,
    check_control,
    selected_streams,
    verify,
)

CORPUS = (
    Path(__file__).resolve().parents[2]
    / "mothra/evidence/gap-remediation/2026-11-13/mac-peer-first-session-01"
)


def copy_corpus(target: Path) -> Path:
    return Path(shutil.copytree(CORPUS, target / "corpus"))


def alter_capture(corpus: Path, name: str, before: bytes, after: bytes) -> None:
    path = corpus / name
    raw = path.read_bytes()
    if before not in raw:
        raise AssertionError("Negative-control source bytes absent")
    path.chmod(0o600)
    path.write_bytes(raw.replace(before, after, 1))
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["capture"][name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


class MacPeerFirstSessionTests(unittest.TestCase):
    def test_complete_finite_capture(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["status"], "verified-partial-session")
        self.assertEqual(result["control_bytes"], {"client": 150, "server": 514})
        self.assertEqual(len(result["http_exchanges"]), 5)
        self.assertEqual(result["last_request_to_fin_us"], 144395409)
        self.assertFalse(result["idle_test_valid"])

    def test_wrong_reply_type_or_id_rejected(self) -> None:
        packets = read_packets(CORPUS / "host-final.pcap")
        _, client, server = selected_streams(
            packets, HOST_CLIENT, HOST_SERVER, CONTROL_CONNECT_US
        )
        for offset, replacement in ((10, b"\x00\x01"), (12, b"\x00\x00\x00\x02")):
            with self.subTest(offset=offset):
                altered = bytearray(server)
                altered[offset : offset + len(replacement)] = replacement
                with self.assertRaisesRegex(ValueError, "reply type/id"):
                    check_control(client, bytes(altered))

    def test_missing_guest_control_bytes_rejected_after_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = copy_corpus(Path(temporary))
            alter_capture(
                corpus,
                "client-guest-final.pcap",
                b"TRTPHOTL",
                b"TRTPHOXX",
            )
            with self.assertRaisesRegex(ValueError, "guest control bytes"):
                verify(corpus)

    def test_missing_http_get_rejected_after_rehash(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            corpus = copy_corpus(Path(temporary))
            alter_capture(
                corpus,
                "client-guest-final.pcap",
                b"GET /zipads/zip-hot.asp",
                b"GEX /zipads/zip-hot.asp",
            )
            with self.assertRaisesRegex(ValueError, "HTTP exchange"):
                verify(corpus)


if __name__ == "__main__":
    unittest.main()
