"""Fault controls for the portable B56/B57 Classic field-162 corpus."""

import copy
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from pcap_tcp import read_packets
from verify_classic_server_name_162 import (
    check_b56,
    check_b57,
    check_capture,
    check_source,
    verify,
)

CORPUS = (
    Path(__file__).resolve().parents[1]
    / "evidence/gap-remediation/2026-11-14/classic-server-name-162-01"
)


class ClassicServerName162Tests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.manifest = json.loads((CORPUS / "manifest.json").read_text())
        cls.packets = {
            "pcaps/" + p.name: read_packets(p)
            for p in (CORPUS / "pcaps").glob("*.pcap")
        }

    def setUp(self) -> None:
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.base = Path(self.tmp.name)

    def copy(self, relative: str) -> Path:
        target = self.base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CORPUS / relative, target)
        return target

    def report(self) -> Path:
        return self.copy("b57/proxy/report.json")

    def b57(self, *, manifest: dict | None = None, packets: dict | None = None) -> dict:
        if not (self.base / "b57/proxy/report.json").exists():
            self.report()
        for name in (
            "units-terminal.txt",
            "listeners-terminal.txt",
            "active-native-terminal.txt",
            "original-fds-terminal.txt",
            "emulators-terminal.txt",
            "ns-v4-routes-terminal.txt",
            "ns-v6-routes-terminal.txt",
        ):
            self.copy("b57/" + name)
        return check_b57(self.base, manifest or self.manifest, packets or self.packets)

    def test_portable_corpus_replays(self) -> None:
        result = verify(CORPUS)
        self.assertEqual(result["b56"]["namespace_packets"], 0)
        self.assertEqual(result["b57"]["banner_bytes"], [16, 58])
        self.assertEqual(result["b57"]["fields"]["162"], b"fixture-native".hex())

    def test_changed_frozen_proxy_source_rejected(self) -> None:
        path = self.copy("as-run/classic_login_proxy.py.txt")
        path.write_bytes(path.read_bytes() + b"\n")
        with self.assertRaisesRegex(ValueError, "proxy source snapshot"):
            check_source(self.base, self.manifest["source"])

    def test_wrong_162_in_guest_ack_rejected(self) -> None:
        path = self.copy("pcaps/client-guest-post.pcap")
        raw = path.read_bytes()
        self.assertIn(b"fixture-native", raw)
        path.write_bytes(raw.replace(b"fixture-native", b"fixture-nativf", 1))
        packets = dict(self.packets)
        packets["pcaps/client-guest-post.pcap"] = read_packets(path)
        with self.assertRaisesRegex(ValueError, "downstream parity|sole ACK rewrite"):
            self.b57(packets=packets)

    def test_wrong_delivered_banner_byte_rejected(self) -> None:
        path = self.copy("pcaps/client-guest-post.pcap")
        raw = path.read_bytes()
        self.assertIn(b"GIF89a", raw)
        path.write_bytes(raw.replace(b"GIF89a", b"GIF89b", 1))
        packets = dict(self.packets)
        packets["pcaps/client-guest-post.pcap"] = read_packets(path)
        with self.assertRaisesRegex(
            ValueError, "downstream parity|banner reference/data"
        ):
            self.b57(packets=packets)

    def test_missing_fifth_view_rejected(self) -> None:
        manifest = copy.deepcopy(self.manifest)
        manifest["b57"]["routes"]["control"].pop()
        with self.assertRaisesRegex(ValueError, "five views"):
            self.b57(manifest=manifest)

    def test_banner_reference_mismatch_rejected(self) -> None:
        path = self.copy("pcaps/client-guest-post.pcap")
        raw = path.read_bytes()
        offset = raw.find(b"HTXF")
        self.assertGreater(offset, 0)
        changed = bytearray(raw)
        changed[offset + 4] ^= 1
        path.write_bytes(changed)
        packets = dict(self.packets)
        packets["pcaps/client-guest-post.pcap"] = read_packets(path)
        with self.assertRaisesRegex(
            ValueError, "upstream parity|banner reference/data"
        ):
            self.b57(packets=packets)

    def test_late_cutoff_rejected(self) -> None:
        path = self.report()
        report = json.loads(path.read_text())
        report["observation"]["relay_teardown_ns"] = (
            report["observation"]["ack_sent_monotonic_ns"] + 31_000_000_000
        )
        path.write_text(json.dumps(report))
        with self.assertRaisesRegex(ValueError, "cutoff timing"):
            self.b57()

    def capture(self, *, label: str = "b57") -> None:
        for kind in ("host", "ns"):
            for phase in ("launch", "before-a7", "before-connect"):
                self.copy(f"{label}/{kind}-ready-{phase}.json")
            journal = (
                f"{label}/mothra-{label}-{kind}-capture-journal.txt"
                if label == "b57"
                else f"{label}/{kind if kind == 'host' else 'ns'}-recorder-journal.txt"
            )
            self.copy(journal)
        self.copy(f"{label}/units-terminal.txt")

    def test_capture_drop_rejected(self) -> None:
        self.capture()
        path = self.base / "b57/mothra-b57-ns-capture-journal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel"
            )
        )
        with self.assertRaisesRegex(ValueError, "recorder drops"):
            check_capture(self.base, "b57", self.manifest)

    def test_dead_capture_unit_rejected(self) -> None:
        self.capture()
        path = self.base / "b57/units-terminal.txt"
        path.write_text(path.read_text().replace("MainPID=0", "MainPID=42", 1))
        with self.assertRaisesRegex(ValueError, "recorder cleanup"):
            check_capture(self.base, "b57", self.manifest)

    def test_b56_mislabelled_as_peer_rejection_rejected(self) -> None:
        for name in (
            "terminal.json",
            "namespace.pcap",
            "client-guest-pre.pcap",
            "client-guest-post.pcap",
            "proxy-journal.txt",
            "units-terminal.txt",
            "listeners-terminal.txt",
        ):
            self.copy("b56/" + name)
        path = self.base / "b56/terminal.json"
        terminal = json.loads(path.read_text())
        terminal["outcome"] = "peer-rejection"
        path.write_text(json.dumps(terminal))
        with self.assertRaisesRegex(ValueError, "B56 failure label"):
            check_b56(self.base)


if __name__ == "__main__":
    unittest.main()
