"""Share the constants and readers of the isolated option-two control witness."""

import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

type Json = dict[str, typ.Any]

EXPECTED = {
    "source_a7": "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e",
    "controller": "afb2dcbabae9765b9708efa21e4e3d7ff74ad33e90bee0f03d953cfa95d1c1da",
    "base": "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910",
    "rom": "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd",
    "emulator": "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4",
    "data": "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
    "rsrc": "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12",
    "stopped": "3717cd5e044bf63eb1e68d131290172a30777743ea073d12ab5b880a0ec4a6b9",
    "banned": "53bec37683dc9bab6cc812f38fa465724085e9c35fc5b7bdf72e25dd09b727d4",
}
PHASES = {"readiness": 18, "guard": 10, "seed": 12, "ban": 32, "probe": 6}
PID = 4127848
START = "5026815"
NS = "net:[4026532619]"
PCAP_HEADER_BYTES = 24  # a capture with no packet is its 24-byte global header
CONTROL_PORT = 15750  # the owned lab port that the plans connect to
GUEST_PORT = 5500  # the port that the guest forwards it to


def need(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the check shape of every verifier
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


def loaded(path: Path) -> Json:
    """Parse a JSON file.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


def digest(path: Path) -> str:
    """Hash a file.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()
