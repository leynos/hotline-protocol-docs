"""Fault controls for the portable B56/B57 Classic field-162 corpus."""

import copy
import dataclasses as dc
import json
import shutil
import typing as typ
from pathlib import Path

import pytest
from pcap_tcp import read_packets
from verify_classic_server_name_162 import (
    check_b56,
    check_b57,
    check_capture,
    check_source,
    verify,
)

# scripts/tests sits two levels below the repository root that holds evidence/.
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-14/classic-server-name-162-01"
)


@dc.dataclass(frozen=True, slots=True)
class Corpus:
    """The manifest and the selected PCAP views of the retained corpus."""

    manifest: dict[str, typ.Any]
    packets: dict[str, list[dict[str, typ.Any]]]


@pytest.fixture(scope="module")
def corpus() -> Corpus:
    """Load the manifest and the selected PCAP views once for the module.

    Returns
    -------
    Corpus
        The parsed manifest and the packets of each selected view.
    """
    return Corpus(
        manifest=json.loads((CORPUS / "manifest.json").read_text()),
        packets={
            "pcaps/" + p.name: read_packets(p)
            for p in (CORPUS / "pcaps").glob("*.pcap")
        },
    )


class ClassicServerName162Tests:
    """Reject each altered frozen source, field, banner, view and recorder fact."""

    @pytest.fixture(autouse=True)
    def _load(self, tmp_path: Path, corpus: Corpus) -> None:
        """Give each test a fresh scratch directory and the shared corpus."""
        self.base = tmp_path
        self.manifest = corpus.manifest
        self.packets = corpus.packets

    def copy(self, relative: str) -> Path:
        """Copy one corpus file into the scratch directory.

        Returns
        -------
        pathlib.Path
            The copy, inside the scratch directory.
        """
        target = self.base / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy2(CORPUS / relative, target)
        return target

    def report(self) -> Path:
        """Copy the B57 proxy report into the scratch directory.

        Returns
        -------
        pathlib.Path
            The copy of the report.
        """
        return self.copy("b57/proxy/report.json")

    def b57(self, *, manifest: dict | None = None, packets: dict | None = None) -> dict:
        """Run the B57 check over the scratch directory with optional changes.

        Returns
        -------
        dict
            The result of the B57 check.
        """
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
        """The retained corpus replays with no contact in B56 and a 16 and 58 banner."""
        result = verify(CORPUS)
        assert result["b56"]["namespace_packets"] == 0, "B56 reached the namespace"
        assert result["b57"]["banner_bytes"] == [16, 58], "the banner sizes differ"
        assert result["b57"]["fields"]["162"] == b"fixture-native".hex(), (
            "the field 162 value differs"
        )

    def test_changed_frozen_proxy_source_rejected(self) -> None:
        """A changed frozen proxy snapshot must fail the source check."""
        path = self.copy("as-run/classic_login_proxy.py.txt")
        path.write_bytes(path.read_bytes() + b"\n")
        with pytest.raises(ValueError, match="proxy source snapshot"):
            check_source(self.base, self.manifest["source"])

    def test_wrong_162_in_guest_ack_rejected(self) -> None:
        """A changed field 162 in the guest ACK must break the rewrite."""
        path = self.copy("pcaps/client-guest-post.pcap")
        raw = path.read_bytes()
        assert b"fixture-native" in raw, "the guest ACK lacks field 162"
        path.write_bytes(raw.replace(b"fixture-native", b"fixture-nativf", 1))
        packets = dict(self.packets)
        packets["pcaps/client-guest-post.pcap"] = read_packets(path)
        with pytest.raises(ValueError, match=r"downstream parity|sole ACK rewrite"):
            self.b57(packets=packets)

    def test_wrong_delivered_banner_byte_rejected(self) -> None:
        """A changed banner byte in the delivered stream must be rejected."""
        path = self.copy("pcaps/client-guest-post.pcap")
        raw = path.read_bytes()
        assert b"GIF89a" in raw, "the delivered banner is missing"
        path.write_bytes(raw.replace(b"GIF89a", b"GIF89b", 1))
        packets = dict(self.packets)
        packets["pcaps/client-guest-post.pcap"] = read_packets(path)
        with pytest.raises(
            ValueError, match=r"downstream parity|banner reference/data"
        ):
            self.b57(packets=packets)

    def test_missing_fifth_view_rejected(self) -> None:
        """A route list with only four views must be refused."""
        manifest = copy.deepcopy(self.manifest)
        manifest["b57"]["routes"]["control"].pop()
        with pytest.raises(ValueError, match="five views"):
            self.b57(manifest=manifest)

    def test_banner_reference_mismatch_rejected(self) -> None:
        """A banner request with a changed reference must be rejected."""
        path = self.copy("pcaps/client-guest-post.pcap")
        raw = path.read_bytes()
        offset = raw.find(b"HTXF")
        assert offset > 0, "the banner request is missing"
        changed = bytearray(raw)
        changed[offset + 4] ^= 1
        path.write_bytes(changed)
        packets = dict(self.packets)
        packets["pcaps/client-guest-post.pcap"] = read_packets(path)
        with pytest.raises(ValueError, match=r"upstream parity|banner reference/data"):
            self.b57(packets=packets)

    def test_late_cutoff_rejected(self) -> None:
        """A teardown after the watchdog window must fail the cutoff timing."""
        path = self.report()
        report = json.loads(path.read_text())
        report["observation"]["relay_teardown_ns"] = (
            report["observation"]["ack_sent_monotonic_ns"] + 31_000_000_000
        )
        path.write_text(json.dumps(report))
        with pytest.raises(ValueError, match="cutoff timing"):
            self.b57()

    def capture(self, *, label: str = "b57") -> None:
        """Copy the recorder receipts, journals and units of one run."""
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
        """A recorder that dropped a packet in the kernel must be rejected."""
        self.capture()
        path = self.base / "b57/mothra-b57-ns-capture-journal.txt"
        path.write_text(
            path.read_text().replace(
                "0 packets dropped by kernel", "1 packets dropped by kernel"
            )
        )
        with pytest.raises(ValueError, match="recorder drops"):
            check_capture(self.base, "b57", self.manifest)

    def test_dead_capture_unit_rejected(self) -> None:
        """A recorder unit that is still running must fail the cleanup check."""
        self.capture()
        path = self.base / "b57/units-terminal.txt"
        path.write_text(path.read_text().replace("MainPID=0", "MainPID=42", 1))
        with pytest.raises(ValueError, match="recorder cleanup"):
            check_capture(self.base, "b57", self.manifest)

    def test_b56_mislabelled_as_peer_rejection_rejected(self) -> None:
        """A B56 run relabelled as a peer rejection must fail the label check."""
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
        with pytest.raises(ValueError, match="B56 failure label"):
            check_b56(self.base)
