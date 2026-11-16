"""Pinned hashes, frames, expected shapes and primitives of the field-162 verifier."""

import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

RAW_ACK = bytes.fromhex(
    "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
)
FORWARDED_ACK = bytes.fromhex(
    "0001000000000001000000000000002000000020000300a0000200be00a100020000"
    "00a2000e666978747572652d6e6174697665"
)
PROXY_SHA = "586d31f204ea1f2782a63346f7a4069d5e6f8f6112bba931488a4e687c25ccea"
PARSER_SHA = "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7"
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
FILP_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
CLIENT_HELLO = bytes.fromhex("54525450484f544c00010002")
SERVER_HELLO = bytes.fromhex("5452545000000000")
FIELDS = {160: bytes.fromhex("00be"), 161: b"\0\0", 162: b"fixture-native"}
ROUTES = (
    "client-guest-post.pcap",
    "namespace.pcap",
    "namespace.pcap",
    "host.pcap",
    "server-guest-post.pcap",
)
AGREEMENT_BYTES = 242
AGREEMENT_ACTION = 6  # the A7 action whose first field carries the agreement
PCAP_HEADER_HEX = "d4c3b2a10200040000000000000000000000040001000000"
PCAP_VIEWS = 4  # the selected PCAP views that the corpus must carry
HTXF_BYTES = 16  # the banner request header
GIF_BYTES = 58  # the delivered banner


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    reason: str,
) -> None:
    """Keep checks active even when Python runs with optimization enabled.

    Raises
    ------
    ValueError
        With ``reason``, when ``condition`` is false.
    """
    if not condition:
        raise ValueError(reason)


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of ``data``.

    Returns
    -------
    str
        The lower-case hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def load(path: Path) -> dict[str, typ.Any]:
    """Parse the JSON document at ``path``.

    Returns
    -------
    dict[str, typing.Any]
        The decoded document.
    """
    return json.loads(path.read_text())
