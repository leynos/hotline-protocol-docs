"""Reject conflated native/fixture evidence and unsupported receiver claims."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from native_plan import packet, payload
from pcap_tcp import read_packets
from serve_shx_fixture import fixture_frames
from shx_syscalls import socket_io
from verify_native_shx import check_packets, check_semantics, fields, frames, sha
from verify_native_shx_extras import receiver, verify

BATCH = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-13/native-shx-02"
)


class PeerExtraTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.host = read_packets(BATCH / "host.pcap")
        cls.guest = read_packets(BATCH / "guest.pcap")
        cls.original = fixture_frames(BATCH.parent)
        cls.sources = {sha(p) for p in (BATCH / "sources").iterdir()}

    def test_all_native_and_controlled_receiver_cases(self) -> None:
        result = verify(BATCH)
        self.assertEqual(
            (result["native_sessions"], result["controlled_receiver_sessions"]), (3, 4)
        )

    def test_actual_native162_is_not_utf8_reencoded(self) -> None:
        case = BATCH / "captures/macroman"
        connections = check_packets(case, self.host, self.guest)
        original = connections[0]["received"]
        ack = frames(original[8:])[0]
        values = fields(ack)
        values[162] = b"mothra-peer-" + "ö".encode()
        changed = bytes.fromhex(packet(0, 1, payload(list(values.items())), reply=1))
        connections[0]["received"] = (
            original[:8] + changed + original[28 + ack["data_size"] :]
        )
        agreement = (
            (BATCH.parent / "native-agreement-01/original-agreement.data")
            .read_bytes()
            .replace(b"\r\n", b"\r")
        )
        with self.assertRaisesRegex(ValueError, "login extras differ"):
            check_semantics(
                case,
                connections,
                agreement,
                kind="basic-empty-name",
                login_name=b"mothra-peer-\x9a",
            )

    def test_unknown_banner_must_be_dumped_exactly(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "banner"
            shutil.copytree(BATCH / "receivers/banner", case)
            (case / "work/hx.dump").write_bytes(b"not the banner")
            with self.assertRaisesRegex(ValueError, "banner dump differs"):
                receiver(
                    case,
                    BATCH / "fixture-servers/banner",
                    self.host,
                    self.original,
                    self.sources,
                )

    def test_subject_addition_does_not_replace_native_roster_records(self) -> None:
        original = copy.deepcopy(self.original)
        roster = frames(original["roster"])[0]
        value = bytes.fromhex(roster["fields"][0]["hex"])
        original["roster"] = bytes.fromhex(
            packet(0, 2, payload([(300, b"\0\0" + value[2:])]), reply=1)
        )
        with self.assertRaisesRegex(ValueError, "native roster bytes differ"):
            receiver(
                BATCH / "receivers/subject",
                BATCH / "fixture-servers/subject",
                self.host,
                original,
                self.sources,
            )

    def test_controlled_listener_cannot_be_claimed_as_native_execution(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            server = Path(temporary)
            report = json.loads(
                (BATCH / "fixture-servers/control/report.json").read_text()
            )
            report["profile"] = "native-mac-oracle"
            (server / "report.json").write_text(json.dumps(report))
            with self.assertRaisesRegex(ValueError, "controlled fixture report"):
                receiver(
                    BATCH / "receivers/control",
                    server,
                    self.host,
                    self.original,
                    self.sources,
                )

    def test_control_session_cannot_be_dropped_from_the_matrix(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            directory = Path(temporary)
            manifest = json.loads((BATCH / "manifest.json").read_text())
            manifest["receiver_cases"].remove("control")
            (directory / "manifest.json").write_text(json.dumps(manifest))
            for name in manifest["native_cases"]:
                (directory / "captures" / name).mkdir(parents=True)
            with self.assertRaisesRegex(ValueError, "receiver inventory differs"):
                verify(directory)

    def test_fixture_port_requires_explicit_analysis_scope(self) -> None:
        trace = (BATCH / "receivers/control/syscalls.log").read_text()
        with self.assertRaisesRegex(ValueError, "Unexpected TCP fixture endpoint"):
            socket_io(trace)
        self.assertTrue(socket_io(trace, server_ports=frozenset({15510})))

    def test_post_banner_chat_must_match_independent_packets(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            case = Path(temporary) / "banner"
            shutil.copytree(BATCH / "receivers/banner", case)
            path = case / "syscalls.log"
            text = path.read_text()
            marker = "".join(f"\\x{b:02x}" for b in b"mothra-shx-basic-chat")
            lines = text.splitlines(keepends=True)
            found = False
            for index, line in enumerate(lines):
                if "write(" in line and "<TCP:" in line and marker in line:
                    lines[index] = line.replace(marker, marker[:-2] + "55")
                    found = True
            self.assertTrue(found)
            path.write_text("".join(lines))
            with self.assertRaisesRegex(
                ValueError, "Independent receiver packet bytes differ"
            ):
                receiver(
                    case,
                    BATCH / "fixture-servers/banner",
                    self.host,
                    self.original,
                    self.sources,
                )


if __name__ == "__main__":
    unittest.main()
