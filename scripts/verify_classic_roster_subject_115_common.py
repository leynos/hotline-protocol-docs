"""Hold the pinned hashes, the fixed replay values and the shared checks.

The roster-115 verifier is split across several modules. This one is imported by
all of them and re-exported by ``verify_classic_roster_subject_115``.
"""

import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

PROXY_SHA = "cbea168a5b77fdf7ab1c7cacf5119b36149723d0725748b592f2768e22664379"
PARSER_SHA = "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7"
RAW_ACK_SHA = "814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0"
RAW_ROSTER_SHA = "9652ca8dee63462016f49e25c4e8cfe80900ed665e0b93d3386fd9d3016a4f90"
FORWARDED_ROSTER_SHA = (
    "6a094bcad87575dfd2df90589b6a5165ab5a7cdd3bed7ee2f07869f3b3d1c549"
)
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
FILP_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
CAPTURE_GATE_SHA = "7a75f4b78f1255f4486ced44fc5fb8882d6008c7de6844a82f4c107e7299d678"
HEADER = bytes.fromhex("d4c3b2a10200040000000000000000000000040001000000")
ROUTES = (
    "client-guest-post.pcap",
    "namespace.pcap",
    "namespace.pcap",
    "host.pcap",
    "server-guest-post.pcap",
)

type Packets = dict[str, list[dict[str, typ.Any]]]


def sha(data: bytes) -> str:
    """Hash ``data`` with SHA-256.

    Returns
    -------
    str
        The lowercase hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()


def need(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass a condition positionally
    reason: str,
) -> None:
    """Raise ``ValueError`` with ``reason`` unless ``ok`` holds.

    Raises
    ------
    ValueError
        With ``reason``, when ``ok`` is false.
    """
    if not ok:
        raise ValueError(reason)


def load(path: Path) -> dict[str, typ.Any]:
    """Parse the JSON document at ``path``.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())
