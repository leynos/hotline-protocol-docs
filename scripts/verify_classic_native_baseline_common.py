"""Pinned hashes, expected shapes and the check primitives of the native baseline."""

import hashlib

FILP_SHA = "7d1f5bf5e2b69b8a18906633ce2ef550876b78252c0639e7d36eb61142787ab8"
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
DATA_SHA = "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"
RSRC_SHA = "40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5"
PROXY_SHA = "44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e"
PARSER_SHA = "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7"
STATIC_ACTIONS = (4, 5, 6, 8, 10, 12, 16, 23, 27)
AGREEMENT_BYTES = 242
FILP_BYTES = 1_049_073
REPLAY_ACTIONS = 29  # the actions each A7 replay must complete
ACCOUNT_COUNT = 2  # the accounts listed by the A7 replay
FILE_COUNT = 41  # the files listed by the A7 replay
VIEW_COUNT = 5  # the capture views that must carry one identical stream
HTXF_BYTES = 16  # the banner request header
GIF_BYTES = 58  # the delivered banner
CLIENT_NETNS_INODE = 4026532479  # the client namespace of the retained run
CUTOFF_NS = 28_000_000_000  # the intentional cutoff target
WATCHDOG_LIMIT_NS = 30_000_000_000  # the proxy must tear down within this bound
MISSING_DATA_MESSAGE = "Missing B47 data"


def require(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    message: str,
) -> None:
    """Keep checks active even when Python runs with optimization enabled.

    Raises
    ------
    ValueError
        With ``message``, when ``condition`` is false.
    """
    if not condition:
        raise ValueError(message)


def digest(data: bytes) -> str:
    """Return the SHA-256 hex digest of ``data``.

    Returns
    -------
    str
        The lower-case hexadecimal digest.
    """
    return hashlib.sha256(data).hexdigest()
