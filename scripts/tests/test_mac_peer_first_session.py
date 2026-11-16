"""Negative controls for the bounded Classic client session verifier."""

import hashlib
import json
import shutil
from pathlib import Path

import pytest
from pcap_tcp import read_packets
from verify_mac_peer_first_session import (
    CONTROL_CONNECT_US,
    HOST_CLIENT,
    HOST_SERVER,
    check_control,
    selected_streams,
    verify,
)

# scripts/tests sits two levels below the repository root that holds evidence/.
CORPUS = (
    Path(__file__).resolve().parents[2]
    / "evidence/gap-remediation/2026-11-13/mac-peer-first-session-01"
)


def copy_corpus(target: Path) -> Path:
    """Copy the retained corpus beneath the target directory.

    Returns
    -------
    pathlib.Path
        The copied corpus directory.
    """
    return Path(shutil.copytree(CORPUS, target / "corpus"))


def alter_capture(corpus: Path, name: str, before: bytes, after: bytes) -> None:
    """Replace bytes in one capture and rehash it, so only the semantic check fails."""
    path = corpus / name
    raw = path.read_bytes()
    assert before in raw, "Negative-control source bytes absent"
    path.chmod(0o600)
    path.write_bytes(raw.replace(before, after, 1))
    manifest_path = corpus / "manifest.json"
    manifest = json.loads(manifest_path.read_text())
    manifest["capture"][name]["sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    manifest_path.write_text(json.dumps(manifest))


class MacPeerFirstSessionTests:
    """Negative controls for the finite Classic client capture."""

    def test_complete_finite_capture(self) -> None:
        """The retained capture verifies with the counts it records."""
        result = verify(CORPUS)
        assert result["status"] == "verified-partial-session", "the status differs"
        assert result["control_bytes"] == {"client": 150, "server": 514}, (
            "the control byte counts differ"
        )
        assert len(result["http_exchanges"]) == 5, "the HTTP exchange count differs"
        assert result["last_request_to_fin_us"] == 144395409, (
            "the final request to FIN span differs"
        )
        assert not result["idle_test_valid"], "the idle test is marked valid"

    def test_wrong_reply_type_or_id_rejected(self) -> None:
        """A changed reply type or identifier fails the control reply check."""
        packets = read_packets(CORPUS / "host-final.pcap")
        _, client, server = selected_streams(
            packets, HOST_CLIENT, HOST_SERVER, CONTROL_CONNECT_US
        )
        for offset, replacement in ((10, b"\x00\x01"), (12, b"\x00\x00\x00\x02")):
            altered = bytearray(server)
            altered[offset : offset + len(replacement)] = replacement
            with pytest.raises(ValueError, match="reply type/id"):
                check_control(client, bytes(altered))

    def test_missing_guest_control_bytes_rejected_after_rehash(
        self, tmp_path: Path
    ) -> None:
        """A rehashed control byte change in the client capture fails the NAT check."""
        corpus = copy_corpus(tmp_path)
        alter_capture(
            corpus,
            "client-guest-final.pcap",
            b"TRTPHOTL",
            b"TRTPHOXX",
        )
        with pytest.raises(ValueError, match="guest control bytes"):
            verify(corpus)

    def test_missing_http_get_rejected_after_rehash(self, tmp_path: Path) -> None:
        """A rehashed change to the external GET fails the HTTP exchange check."""
        corpus = copy_corpus(tmp_path)
        alter_capture(
            corpus,
            "client-guest-final.pcap",
            b"GET /zipads/zip-hot.asp",
            b"GEX /zipads/zip-hot.asp",
        )
        with pytest.raises(ValueError, match="HTTP exchange"):
            verify(corpus)
