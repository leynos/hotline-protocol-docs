"""Name the constants and helpers that the rate304 partial verifier modules share.

The digests and ports below are the as-run values of the retained first-pair
corpus. Each is a fixed expected value, not one derived at run time.
"""

import hashlib
import json
import typing as typ

from verify_native_core import require as need

if typ.TYPE_CHECKING:
    from pathlib import Path

CASES = "1f03bde7d498f7831c82e87e09ec3e7d02bc43124a56cd1411e985546220e43f"
RUNNER = "a1d57bc585d145e03d7c499ee5896477d03c0da83a8a6483b65c32dbd88559b5"
PLAN = "d5f689b36f8532ab806a894d6875747d75e1ee14c046a98e6d03bf43e7ab0bf2"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
FORKS = {
    "admin": "26612ad46cd91b90050feacf517d32a9e56d4a4aa92fbe6618eaf6e9e5ac60a3",
    "fixture-low": "fce81359d0efcfc6c2dbf42852db66b0fb7a404b2889162b8f8fad81361ce2d5",
    "Prefs": "4ed2b3e14e6e8a6cf246d16f7d1b98f0b91d1b09f6ab5497de1056a6f617d196",
    "server-data": DATA,
    "server-rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
    "board": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
}
PORTS = {"main": 53738, "observer": 44482, "paced": 44496}
CONTROL_PORT = 15880  # the reserved control port of the case plan

# The names below are imported by the other verify_native_rate304_partial modules
# and by verify_native_rate304_partial itself, which re-exports them.
__all__ = [
    "CASES",
    "CONTROL_PORT",
    "DATA",
    "FORKS",
    "PLAN",
    "PORTS",
    "RUNNER",
    "fields",
    "need",
    "read",
    "sha",
]


def sha(path: Path) -> str:
    """Return the SHA-256 hexadecimal digest of a file's bytes.

    Returns
    -------
    str
        The lowercase hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()


def read(path: Path) -> dict:
    """Read and parse one JSON file.

    Returns
    -------
    dict
        The parsed JSON object.
    """
    return json.loads(path.read_text())


def fields(frame: dict) -> dict[int, bytes]:
    """Return the fields of one decoded frame, keyed by field ID.

    Returns
    -------
    dict[int, bytes]
        Each field ID with its decoded bytes.
    """
    return {item["id"]: bytes.fromhex(item["hex"]) for item in frame["fields"]}
