"""Hold the constants and the shared checks of the persisted-ban reload witness.

The verifier modules that split the witness import these names. The module
verify_native_ban_reload re-exports every public one.
"""

import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

CORPUS = "native-ban-reload-01"
C56_MANIFEST = "8e8497212614ae32b1b03a8c27b8aa28fcf595ef1704f056420ac18fd7cc9629"
DATA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
RSRC = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
BASE = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
EMULATOR = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
IMAGE_BEFORE = "3717cd5e044bf63eb1e68d131290172a30777743ea073d12ab5b880a0ec4a6b9"
IMAGE_AFTER = "1a0f7ede44b2261ca0e2d264d25833337a5f0780bdf02b7f228b678233f00b64"
BAN = "53bec37683dc9bab6cc812f38fa465724085e9c35fc5b7bdf72e25dd09b727d4"
PREPARED = "3d1c69bb2c03625df891c44370ad3f8dd90c2d907d4808a6469b644f2e0ef0dc"
UI_IMAGE = "10bce764a04be6479dd17a9409d544d5f0107ba8781cf26386be4887c6322c3d"
INPUT = "b07976522f664a05ef5e3df33e2719b70c49d86ef7f99c8a892344284a07cd9e"
PID, START, NS = 415512, "5324681", "net:[4026533397]"
NOTICE = b"You are permanently banned on this server."

# Sizes and counts that the retained witness fixes.
UI_ACTIONS = 8  # the recorded actions of the read-only Ban tab
EMPTY_PCAP_BYTES = 24  # a recorder file with its global header and no packet
PROBE_STEPS = 6  # the steps of the one-probe vector
NAMESPACE_PACKETS = 13  # the packets of the namespace recorder
GUEST_PACKETS = 12  # the packets of the guest recorder
MANAGED_UNITS = 7  # the managed units that the cleanup retires


def require(
    value: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the check positionally
    reason: str,
) -> None:
    """Keep a check active even when Python runs with optimization enabled.

    Parameters
    ----------
    value : bool
        The check that must hold.
    reason : str
        The message of the error that a failed check raises.

    Raises
    ------
    ValueError
        With ``reason``, when ``value`` is false.
    """
    if not value:
        raise ValueError(reason)


def read(path: Path) -> Report:
    """Parse a JSON file.

    Parameters
    ----------
    path : pathlib.Path
        The file to read.

    Returns
    -------
    dict[str, typing.Any]
        The parsed value.
    """
    return json.loads(path.read_text())


def sha(path: Path) -> str:
    """Return the SHA-256 digest of the bytes of a file.

    Parameters
    ----------
    path : pathlib.Path
        The file to hash.

    Returns
    -------
    str
        The hexadecimal digest.
    """
    return hashlib.sha256(path.read_bytes()).hexdigest()
