#!/usr/bin/env python3
"""Verify the redacted A22 witness; private mode checks withheld raw packets."""

import hashlib
import json
import sys
import tomllib
import typing as typ
from pathlib import Path

from native_wire_names import FIELD_PASSWORD, TYPE_LOGIN
from script_cli import UsageError, run

type Manifest = dict[str, typ.Any]
type Witness = dict[str, typ.Any]

ROOT = Path(__file__).resolve().parents[1]
CORPUS = ROOT / "evidence/gap-remediation/2026-11-13/mxd-classic-login-01"
LOGIN_REQUEST_BYTES = 59  # the login request's total size, equal to its data size
SECRET_BYTES = 48  # the length of the create-user password in the seed
WIRE_PASSWORD_BYTES = 31  # the length of the password field on the wire
COMPLEMENT_MASK = 255  # the wire complements each password byte
SYN_FLAG = 2  # the TCP SYN bit in a packet's flags
HOST_PACKETS = 14  # the packets in the host-side namespace capture
GUEST_DELTA_PACKETS = 11  # the packets that the guest sent after the pre capture
PAIR_USAGE = "--raw-session and --seed must be provided together"


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of ``data``.

    Returns
    -------
    str
        The hexadecimal SHA-256 digest.
    """
    return hashlib.sha256(data).hexdigest()


def need(*, ok: bool) -> None:
    """Stop at the first retained fact that does not hold.

    Parameters
    ----------
    ok : bool
        Whether the retained fact holds.

    Raises
    ------
    AssertionError
        When ``ok`` is false, with no message.
    """
    if not ok:
        raise AssertionError


def check_checksums(corpus: Path, manifest: Manifest) -> set[str]:
    """Check each listed file's digest and the checksum inventory.

    Parameters
    ----------
    corpus : pathlib.Path
        The redacted witness directory.
    manifest : Manifest
        The parsed ``manifest.json``.

    Returns
    -------
    set[str]
        The names that the checksum file lists.

    Raises
    ------
    AssertionError
        When a listed file's digest or the checksum inventory differs.
    """
    listed: set[str] = set()
    for line in (corpus / "SHA256SUMS").read_text().splitlines():
        expected, name = line.split("  ", 1)
        need(ok=name in manifest["published"] + ["manifest.json"])
        need(ok=name not in listed)
        if digest((corpus / name).read_bytes()) != expected:
            raise AssertionError(name)
        listed.add(name)
    need(ok=listed == set(manifest["published"] + ["manifest.json"]))
    return listed


def check_witness(witness: Witness) -> None:
    """Check the decoded public fields and the private replay facts.

    Parameters
    ----------
    witness : Witness
        The parsed ``redacted-witness.json``.
    """
    public = witness["decoded_public"]
    private = witness["private_replay"]
    need(ok=public["client_handshake_hex"] == "54525450484f544c00010002")
    need(ok=public["server_handshake_hex"] == "5452545000000000")
    need(ok=public["request_type"] == TYPE_LOGIN)
    need(ok=public["request_id"] == 1)
    need(
        ok=public["request_total_size"]
        == public["request_data_size"]
        == LOGIN_REQUEST_BYTES
    )
    need(ok=public["request_field_id_lengths"] == [[105, 12], [106, 31], [160, 2]])
    need(ok=public["reply_header_hex"] == "0001000000000001000000010000000000000000")
    reply = (
        public["reply_type"],
        public["reply_id"],
        public["reply_status"],
        public["reply_payload_length"],
    )
    need(ok=reply == (0, 1, 1, 0))
    need(ok=private["secret_length"] == SECRET_BYTES)
    need(ok=private["wire_field106_length"] == WIRE_PASSWORD_BYTES)
    need(ok=private["credential_bytes_omitted"] is True)
    need(ok=private["guest_delta_native_15500_15501_SYN"] == 0)
    need(ok=witness["runtime"]["namespace_capture_kernel_drops"] == 0)


def verify_public(corpus: Path = CORPUS) -> dict[str, object]:
    """Check the public witness and its checksums, without the raw packets.

    Parameters
    ----------
    corpus : pathlib.Path
        The redacted witness directory.

    Returns
    -------
    dict[str, object]
        The status, the raw-proof status and the number of checked files.
    """
    manifest = json.loads((corpus / "manifest.json").read_text())
    witness = json.loads((corpus / "redacted-witness.json").read_text())
    need(
        ok=manifest["classification"]
        == witness["kind"]
        == "DERIVED_REDACTED_WITNESS_NOT_A_PCAP"
    )
    need(ok=manifest["attempts"] == 1)
    listed = check_checksums(corpus, manifest)
    check_witness(witness)
    terminal = json.loads((corpus / "c19-terminal.json").read_text())
    need(ok=terminal["pid_absent"] is True)
    return {
        "status": "metadata-only",
        "raw_packet_proof": "unavailable",
        "files": len(listed),
    }


def check_raw_captures(raw: Path, witness: Witness) -> None:
    """Check each withheld capture's size and digest, and the pre-capture prefix.

    Parameters
    ----------
    raw : pathlib.Path
        The directory of the withheld raw captures.
    witness : Witness
        The parsed ``redacted-witness.json``.

    Raises
    ------
    AssertionError
        When a capture's size or digest differs, or the pre capture is not a prefix.
    """
    for name, info in witness["raw_ignored_captures"].items():
        data = (raw / name).read_bytes()
        if len(data) != info["bytes"] or digest(data) != info["sha256"]:
            raise AssertionError(name)
    pre_bytes = (raw / "client-guest-pre.pcap").read_bytes()
    post_bytes = (raw / "client-guest-post.pcap").read_bytes()
    need(ok=post_bytes.startswith(pre_bytes))


def check_streams(client: bytes, server: bytes, shown: dict[str, typ.Any]) -> None:
    """Check the reassembled streams against the public lengths and digests.

    Parameters
    ----------
    client : bytes
        The client-to-server stream from the host capture.
    server : bytes
        The server-to-client stream from the host capture.
    shown : dict[str, typing.Any]
        The ``decoded_public`` section of the witness.
    """
    need(ok=len(client) == shown["client_stream_length"])
    need(ok=digest(client) == shown["client_stream_sha256"])
    need(ok=len(server) == shown["server_stream_length"])
    need(ok=digest(server) == shown["server_stream_sha256"])
    need(ok=client[:12].hex() == shown["client_handshake_hex"])
    need(ok=server[:8].hex() == shown["server_handshake_hex"])
    need(ok=server[8:28].hex() == shown["reply_header_hex"])


def check_request_fields(client: bytes, shown: dict[str, typ.Any]) -> dict[int, bytes]:
    """Parse the login request's fields and check their identifiers and lengths.

    Parameters
    ----------
    client : bytes
        The client-to-server stream from the host capture.
    shown : dict[str, typing.Any]
        The ``decoded_public`` section of the witness.

    Returns
    -------
    dict[int, bytes]
        The value of each field, keyed by its identifier.
    """
    payload = client[32:]
    count = int.from_bytes(payload[:2], "big")
    position = 2
    fields: dict[int, bytes] = {}
    for _ in range(count):
        field_id = int.from_bytes(payload[position : position + 2], "big")
        length = int.from_bytes(payload[position + 2 : position + 4], "big")
        fields[field_id] = payload[position + 4 : position + 4 + length]
        position += 4 + length
    need(ok=position == len(payload))
    lengths = [[key, len(value)] for key, value in fields.items()]
    need(ok=lengths == shown["request_field_id_lengths"])
    return fields


def check_password(fields: dict[int, bytes], seed: Path, witness: Witness) -> None:
    """Check the replayed password field against the seed's password.

    Parameters
    ----------
    fields : dict[int, bytes]
        The request fields, keyed by identifier.
    seed : pathlib.Path
        The seed file that holds the create-user password.
    witness : Witness
        The parsed ``redacted-witness.json``.
    """
    password = tomllib.loads(seed.read_text())["cmds"]["create-user"]["password"]
    secret = password.encode("ascii")
    need(ok=len(secret) == SECRET_BYTES)
    need(
        ok=fields[FIELD_PASSWORD]
        == bytes(value ^ COMPLEMENT_MASK for value in secret[:WIRE_PASSWORD_BYTES])
    )
    need(
        ok=digest(fields[FIELD_PASSWORD])
        == witness["private_replay"]["field106_sha256"]
    )


def verify_private(corpus: Path, raw: Path, seed: Path) -> dict[str, object]:
    """Check the public witness, then the withheld raw captures and the seed.

    Parameters
    ----------
    corpus : pathlib.Path
        The redacted witness directory.
    raw : pathlib.Path
        The directory of the withheld raw captures.
    seed : pathlib.Path
        The seed file that holds the create-user password.

    Returns
    -------
    dict[str, object]
        The public result, marked as verified against the raw packets.
    """
    public_result = verify_public(corpus)
    witness = json.loads((corpus / "redacted-witness.json").read_text())
    sys.path.insert(0, str(ROOT.parent / "hotline-protocol-docs" / "scripts"))
    from pcap_tcp import read_packets, stream

    check_raw_captures(raw, witness)
    host = read_packets(raw / "namespace-15650.pcap")
    pre = read_packets(raw / "client-guest-pre.pcap")
    post = read_packets(raw / "client-guest-post.pcap")
    delta = [
        packet
        for packet in post
        if packet["index"] > max(packet["index"] for packet in pre)
    ]
    need(ok=len(host) == HOST_PACKETS)
    need(ok=len(delta) == GUEST_DELTA_PACKETS)
    need(
        ok=not any(
            packet["flags"] & SYN_FLAG and packet["dst_port"] in {15500, 15501}
            for packet in delta
        )
    )
    client = stream(host, ("127.0.0.1", 57360), ("127.0.0.1", 15650))
    server = stream(host, ("127.0.0.1", 15650), ("127.0.0.1", 57360))
    need(ok=client == stream(delta, ("10.0.2.15", 49157), ("10.0.2.2", 15650)))
    need(ok=server == stream(delta, ("10.0.2.2", 15650), ("10.0.2.15", 49157)))
    shown = witness["decoded_public"]
    check_streams(client, server, shown)
    fields = check_request_fields(client, shown)
    check_password(fields, seed, witness)
    public_result.update(status="private-raw-verified", raw_packet_proof="verified")
    return public_result


def show(
    *,
    corpus: str | None = None,
    raw_session: str | None = None,
    seed: str | None = None,
) -> None:
    """Verify the redacted witness, and the withheld raw packets when asked.

    Parameters
    ----------
    corpus : str | None
        The redacted witness directory, or none for the retained corpus.
    raw_session : str | None
        The directory of the withheld raw captures, or none.
    seed : str | None
        The seed file that holds the create-user password, or none.

    Raises
    ------
    UsageError
        When only one of ``raw_session`` and ``seed`` is given.
    """
    corpus_path = CORPUS if corpus is None else Path(corpus)
    if raw_session is None and seed is None:
        result = verify_public(corpus_path)
    elif raw_session is not None and seed is not None:
        result = verify_private(corpus_path, Path(raw_session), Path(seed))
    else:
        raise UsageError(PAIR_USAGE)
    print(json.dumps(result, sort_keys=True))


def main() -> None:
    """Verify the redacted A22 witness; private mode checks withheld raw packets."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
