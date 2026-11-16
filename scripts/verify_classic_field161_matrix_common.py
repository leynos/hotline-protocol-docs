"""Constants, checks and the corpus inventory of the field-161 verifier.

The entry module :mod:`verify_classic_field161_matrix` and its helper modules
import these names from here, so that none of them imports the entry module.
"""

import hashlib
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

SOURCE_ACK_SHA = "814b733a82d15dd7250cb0e8b7ed0c6c09a7a02d7169ab70ebaa359fb18eb6d0"
SOURCE_ACK_HEX = "0001000000000001000000000000000e0000000e000200a0000200be00a100020000"
AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
VARIANTS = ("omit-161", "one-byte-161", "four-byte-161")
SOURCE_SHAS = {
    "proxy": "44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e",
    "parser": "04c4fda2e62ccab35ed306c036dac6b1878af58adbfaccc6312a2805dd6897d7",
}
EXPECTED_FIELDS = {
    "omit-161": {160: bytes.fromhex("00be")},
    "one-byte-161": {160: bytes.fromhex("00be"), 161: b"\0"},
    "four-byte-161": {160: bytes.fromhex("00be"), 161: bytes(4)},
}
VIEWS_PER_STREAM = 5  # the control and data views that each case records
CAPTURE_VIEWS = 4  # the selected PCAP views of the corpus
CAPTURE_FD = 5  # the descriptor that each recorder holds
CAPTURE_OWNERS = (
    ("host", 3394965, 4026531840),  # label, recorder PID, network namespace inode
    ("ns", 3394975, 4026532479),
)
AUDIT_EVENTS = 15  # the audited proxy entries of one case
SERVER_EVENTS = 7  # of which the server sent this many
CLIENT_EVENTS = 3  # and the client sent this many
REWRITTEN_ENTRY = 3  # the server ACK, the only entry whose bytes the proxy changes
DATA_HEADER_BYTES = 16  # the HTXF header of the data connection
DATA_PAYLOAD_BYTES = 58  # the GIF payload that the data connection carries
CUTOFF_NS = 28_000_000_000  # the watchdog's cutoff, 28 seconds after the ACK
TEARDOWN_LIMIT_NS = 30_000_000_000  # the most that teardown may take after the ACK


def digest(data: bytes) -> str:
    """Return the SHA-256 digest of some bytes, in hexadecimal.

    Returns
    -------
    str
        The digest.
    """
    return hashlib.sha256(data).hexdigest()


def require(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
    reason: str,
) -> None:
    """Raise a ValueError with the reason when a retained fact does not hold.

    Raises
    ------
    ValueError
        With ``reason``, when ``ok`` is false.
    """
    if not ok:
        raise ValueError(reason)


def inventory(base: Path) -> None:
    """Check every file of the corpus against its SHA256SUMS inventory.

    Parameters
    ----------
    base : Path
        The corpus directory, which holds ``SHA256SUMS``.
    """
    root = base.resolve().parents[3]
    names = set()
    for line in (base / "SHA256SUMS").read_text().splitlines():
        expected, relative = line.split("  ", 1)
        path = root / relative
        require(
            path.is_file() and path.resolve().is_relative_to(base),
            "inventory path escapes corpus",
        )
        require(relative not in names, "duplicate inventory path")
        names.add(relative)
        require(digest(path.read_bytes()) == expected, f"SHA inventory {relative}")
    actual = {
        str(p.relative_to(root))
        for p in base.rglob("*")
        if p.is_file() and p.name != "SHA256SUMS"
    }
    require(names == actual, "SHA inventory file set")
