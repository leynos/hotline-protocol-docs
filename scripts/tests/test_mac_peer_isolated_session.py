"""Semantic negative controls for the finite isolated Mac client corpus."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
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

# scripts/tests sits two levels below the repository root that holds evidence/.
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/mac-peer-isolated-session-01"
)


def changed_capture(corpus: Path, name: str, before: bytes, after: bytes) -> None:
    """Replace bytes in one capture and rehash it, so only the semantic check fails."""
    path = corpus / name
    raw = path.read_bytes()
    assert before in raw, "Negative-control bytes absent"
    path.write_bytes(raw.replace(before, after, 1))
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["capture"][name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


class IsolatedMacSessionTests:
    """Semantic negative controls for the finite isolated Mac client corpus."""

    def test_complete_bounded_session(self) -> None:
        """The retained isolated session verifies with the counts it records."""
        result = verify(CORPUS)
        assert result["status"] == "verified-isolated-finite-session", (
            "the status differs"
        )
        assert result["control_bytes"] == {"client": 150, "server": 514}, (
            "the control byte counts differ"
        )
        assert result["data_bytes"] == {"client": 16, "server": 58}, (
            "the data byte counts differ"
        )
        assert result["control"]["uid"] == 14, "the roster UID differs"
        assert result["control"]["data_reference_hex"] == "002e037f", (
            "the data reference differs"
        )
        assert result["dns"]["matched_unreachable"] == 15, (
            "the matched DNS error count differs"
        )
        assert result["data_last_to_quiet_end_us"] > 130_000_000, (
            "the quiet window is shorter than 130 seconds"
        )
        assert not result["banner_ui_complete"], "the banner UI is marked complete"

    def test_guest_control_byte_mismatch_rejected_after_rehash(
        self, tmp_path: Path
    ) -> None:
        """A rehashed control byte change in the client capture fails the NAT check."""
        corpus = Path(shutil.copytree(CORPUS, tmp_path / "corpus"))
        changed_capture(corpus, "client-guest-final.pcap", b"TRTPHOTL", b"TRTPHOXX")
        with pytest.raises(ValueError, match="Control bytes differ across NAT"):
            verify(corpus)

    def test_wrong_161_rejected(self) -> None:
        """A changed login 161 field fails the control reply check."""
        packets = read_packets(CORPUS / "host-final.pcap")
        control_syn = syn(packets, "127.0.0.1", "127.0.0.1", 15500)
        _, client, server = flow(packets, control_syn)
        old = b"\x00\xa1\x00\x02\x00\x00"
        assert old in server, "the login 161 bytes are absent"
        changed = server.replace(old, b"\x00\xa1\x00\x02\x00\x01", 1)
        with pytest.raises(ValueError, match="Login 161"):
            check_control(client, changed)

    def test_dynamic_ref_must_match_data_header(self) -> None:
        """A data reference that differs from the data header fails the data check."""
        packets = read_packets(CORPUS / "host-final.pcap")
        data_syn = syn(packets, "127.0.0.1", "127.0.0.1", 15501)
        _, sent, received = flow(packets, data_syn)
        check_data(bytes.fromhex("002e037f"), sent, received)
        with pytest.raises(ValueError, match="Dynamic 212/data"):
            check_data(bytes.fromhex("002e037e"), sent, received)

    def test_changed_dns_error_rejected_from_packet_bytes(self, tmp_path: Path) -> None:
        """A changed DNS error type and code in the guest capture is rejected."""
        changed = tmp_path / "guest.pcap"
        raw = (CORPUS / "client-guest-final.pcap").read_bytes()
        marker = b"\x03\x00\xb9\x29"
        assert marker in raw, "the DNS error bytes are absent"
        changed.write_bytes(raw.replace(marker, b"\x03\x01\xb9\x29", 1))
        with pytest.raises(ValueError, match="DNS error type/code"):
            check_dns_and_egress(changed, utc_us(CORPUS / "disconnect-time.txt"))

    def test_unexpected_host_observer_record_rejected(self, tmp_path: Path) -> None:
        """An observer capture with a packet after its header is rejected."""
        changed = tmp_path / "observer.pcap"
        changed.write_bytes(
            (CORPUS / "nonlocal-known-ip.pcap").read_bytes() + b"\x00" * 16
        )
        with pytest.raises(ValueError, match="Unexpected public-IP"):
            check_observer(changed)

    def test_shortened_observation_rejected(self, tmp_path: Path) -> None:
        """A quiet end time that leaves too short a window is rejected."""
        corpus = Path(shutil.copytree(CORPUS, tmp_path / "corpus"))
        (corpus / "quiet-end-time.txt").write_text("2026-11-13 19:58:00 UTC\n")
        with pytest.raises(ValueError, match="Finite quiet window"):
            verify(corpus)
