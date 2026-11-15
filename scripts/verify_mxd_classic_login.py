#!/usr/bin/env python3
"""Verify the redacted A22 witness; private mode checks withheld raw packets."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

import tomllib

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-13/mxd-classic-login-01"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def verify_public(corpus: Path = CORPUS) -> dict[str, object]:
    manifest = json.loads((corpus / "manifest.json").read_text())
    witness = json.loads((corpus / "redacted-witness.json").read_text())
    assert (
        manifest["classification"]
        == witness["kind"]
        == "DERIVED_REDACTED_WITNESS_NOT_A_PCAP"
    )
    assert manifest["attempts"] == 1
    checksums = (corpus / "SHA256SUMS").read_text().splitlines()
    listed = set()
    for line in checksums:
        expected, name = line.split("  ", 1)
        assert name in manifest["published"] + ["manifest.json"] and name not in listed
        assert digest((corpus / name).read_bytes()) == expected, name
        listed.add(name)
    assert listed == set(manifest["published"] + ["manifest.json"])
    public = witness["decoded_public"]
    private = witness["private_replay"]
    assert public["client_handshake_hex"] == "54525450484f544c00010002"
    assert public["server_handshake_hex"] == "5452545000000000"
    assert public["request_type"] == 107 and public["request_id"] == 1
    assert public["request_total_size"] == public["request_data_size"] == 59
    assert public["request_field_id_lengths"] == [[105, 12], [106, 31], [160, 2]]
    assert public["reply_header_hex"] == "0001000000000001000000010000000000000000"
    assert (
        public["reply_type"],
        public["reply_id"],
        public["reply_status"],
        public["reply_payload_length"],
    ) == (0, 1, 1, 0)
    assert private["secret_length"] == 48 and private["wire_field106_length"] == 31
    assert private["credential_bytes_omitted"] is True
    assert private["guest_delta_native_15500_15501_SYN"] == 0
    assert witness["runtime"]["namespace_capture_kernel_drops"] == 0
    assert json.loads((corpus / "c19-terminal.json").read_text())["pid_absent"] is True
    return {
        "status": "metadata-only",
        "raw_packet_proof": "unavailable",
        "files": len(listed),
    }


def verify_private(corpus: Path, raw: Path, seed: Path) -> dict[str, object]:
    public_result = verify_public(corpus)
    witness = json.loads((corpus / "redacted-witness.json").read_text())
    sys.path.insert(0, str(ROOT.parent / "hotline-protocol-docs" / "scripts"))
    from pcap_tcp import read_packets, stream

    for name, info in witness["raw_ignored_captures"].items():
        data = (raw / name).read_bytes()
        assert len(data) == info["bytes"] and digest(data) == info["sha256"], name
    pre_bytes = (raw / "client-guest-pre.pcap").read_bytes()
    post_bytes = (raw / "client-guest-post.pcap").read_bytes()
    assert post_bytes.startswith(pre_bytes)
    host = read_packets(raw / "namespace-15650.pcap")
    pre = read_packets(raw / "client-guest-pre.pcap")
    post = read_packets(raw / "client-guest-post.pcap")
    delta = [
        packet
        for packet in post
        if packet["index"] > max(packet["index"] for packet in pre)
    ]
    assert len(host) == 14 and len(delta) == 11
    assert not any(
        packet["flags"] & 2 and packet["dst_port"] in (15500, 15501) for packet in delta
    )
    client = stream(host, ("127.0.0.1", 57360), ("127.0.0.1", 15650))
    server = stream(host, ("127.0.0.1", 15650), ("127.0.0.1", 57360))
    assert client == stream(delta, ("10.0.2.15", 49157), ("10.0.2.2", 15650))
    assert server == stream(delta, ("10.0.2.2", 15650), ("10.0.2.15", 49157))
    shown = witness["decoded_public"]
    assert (
        len(client) == shown["client_stream_length"]
        and digest(client) == shown["client_stream_sha256"]
    )
    assert (
        len(server) == shown["server_stream_length"]
        and digest(server) == shown["server_stream_sha256"]
    )
    assert client[:12].hex() == shown["client_handshake_hex"]
    assert server[:8].hex() == shown["server_handshake_hex"]
    assert server[8:28].hex() == shown["reply_header_hex"]
    payload = client[32:]
    count = int.from_bytes(payload[:2], "big")
    position = 2
    fields = {}
    for _ in range(count):
        field_id = int.from_bytes(payload[position : position + 2], "big")
        length = int.from_bytes(payload[position + 2 : position + 4], "big")
        fields[field_id] = payload[position + 4 : position + 4 + length]
        position += 4 + length
    assert (
        position == len(payload)
        and [[key, len(value)] for key, value in fields.items()]
        == shown["request_field_id_lengths"]
    )
    secret = tomllib.loads(seed.read_text())["cmds"]["create-user"]["password"].encode(
        "ascii"
    )
    assert len(secret) == 48 and fields[106] == bytes(
        value ^ 255 for value in secret[:31]
    )
    assert digest(fields[106]) == witness["private_replay"]["field106_sha256"]
    public_result.update(status="private-raw-verified", raw_packet_proof="verified")
    return public_result


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--corpus", type=Path, default=CORPUS)
    parser.add_argument("--raw-session", type=Path)
    parser.add_argument("--seed", type=Path)
    args = parser.parse_args()
    if bool(args.raw_session) != bool(args.seed):
        parser.error("--raw-session and --seed must be provided together")
    result = (
        verify_private(args.corpus, args.raw_session, args.seed)
        if args.raw_session
        else verify_public(args.corpus)
    )
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    main()
