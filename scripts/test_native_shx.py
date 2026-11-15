"""Reject identity, byte-preservation and fork-completion overclaims."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_plan import packet, payload
from pcap_tcp import read_packets
from shx_syscalls import socket_io
from verify_native_shx import CHAT, check_packets, check_semantics, frames, verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-shx-01"
)


class FullPeerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.host = read_packets(BATCH / "host.pcap")
        cls.guest = read_packets(BATCH / "guest.pcap")
        cls.agreement = (
            (BATCH.parent / "native-agreement-01/original-agreement.data")
            .read_bytes()
            .replace(b"\r\n", b"\r")
        )

    def connections(self, name: str) -> list[dict]:
        return check_packets(BATCH / "captures" / name, self.host, self.guest)

    def test_complete_full_process_corpus(self) -> None:
        result = verify(BATCH)
        self.assertEqual((result["cases"], result["paired_connections"]), (5, 7))

    def test_omitted_native161_cannot_pass_as_extra_field_tolerance(self) -> None:
        name = "basic-empty-name"
        connections = self.connections(name)
        original = connections[0]["received"]
        ack = frames(original[8:])[0]
        boundary = 28 + ack["data_size"]
        changed = bytes.fromhex(packet(0, 1, payload([(160, b"\0\xbe")]), reply=1))
        connections[0]["received"] = original[:8] + changed + original[boundary:]
        with self.assertRaisesRegex(ValueError, "login extras differ"):
            check_semantics(BATCH / "captures" / name, connections, self.agreement)

    def test_high_bytes_cannot_be_replaced_by_ascii(self) -> None:
        name = "ambiguous-text"
        connections = self.connections(name)
        original = connections[0]["received"]
        self.assertIn(CHAT, original)
        connections[0]["received"] = original.replace(CHAT, CHAT.replace(b"\x80", b"?"))
        with self.assertRaisesRegex(ValueError, "ambiguous chat bytes changed"):
            check_semantics(BATCH / "captures" / name, connections, self.agreement)

    def test_wrong_password_is_not_reported_as_success(self) -> None:
        name = "wrong-password"
        connections = self.connections(name)
        changed = bytearray(connections[0]["received"])
        changed[19] = 0
        connections[0]["received"] = bytes(changed)
        with self.assertRaisesRegex(ValueError, "login error differs"):
            check_semantics(BATCH / "captures" / name, connections, self.agreement)

    def test_terminal_completion_does_not_replace_saved_resource_verification(
        self,
    ) -> None:
        source = BATCH / "captures/fork-download"
        connections = self.connections(source.name)
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / source.name
            shutil.copytree(source, case)
            (case / "work/.resource/mothra-fork-fixture").write_bytes(b"wrong")
            with self.assertRaisesRegex(ValueError, "Saved resource fork differs"):
                check_semantics(case, connections, self.agreement)

    def test_syscall_bytes_must_match_the_independent_guest_capture(self) -> None:
        changed = copy.deepcopy(self.guest)
        case = BATCH / "captures/basic-empty-name"
        port = socket_io((case / "syscalls.log").read_text())[0]["client_port"]
        target = next(
            p
            for p in changed
            if p["dst_port"] == 5500
            and p["src_port"] == port
            and p["payload_hex"].startswith("54525450")
        )
        target["payload_hex"] = "00" + target["payload_hex"][2:]
        with self.assertRaisesRegex(ValueError, "guest peer input differs"):
            check_packets(case, self.host, changed)

    def test_missing_required_peer_session_is_rejected(self) -> None:
        manifest = json.loads((BATCH / "manifest.json").read_text())
        manifest["cases"].remove("wrong-password")
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            (directory / "manifest.json").write_text(json.dumps(manifest))
            with self.assertRaisesRegex(ValueError, "corpus inventory differs"):
                verify(directory)

    def test_truncated_strace_strings_are_not_treated_as_complete_bytes(self) -> None:
        trace = '1 123.000001 read(3<TCP:[127.0.0.1:12345->127.0.0.1:15500]>, "\\x61"..., 100) = 20'
        with self.assertRaisesRegex(ValueError, "incomplete TCP syscall"):
            socket_io(trace)

    def test_partial_write_uses_only_the_returned_prefix(self) -> None:
        trace = '1 123.000001 write(3<TCP:[127.0.0.1:12345->127.0.0.1:15500]>, "\\x61\\x62", 2) = 1'
        self.assertEqual(socket_io(trace)[0]["bytes"], b"a")


if __name__ == "__main__":
    unittest.main()
