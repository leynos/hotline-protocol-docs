"""Hold the constants and the shared checks of the option-one ban witness.

The verifier modules that split the witness import these names. The module
verify_native_ban_one re-exports every public one.
"""

import hashlib
import json
import typing as typ

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

BASE_PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
SOURCE_DISK_SHA = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"
ROM_SHA = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
APP_DATA_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
APP_RSRC_SHA = "fe83a2cfaacd80e998a8ca274a828a0196d5cd5c4db59b06c1763cb3c1c48b12"
NOTICE = b"You are temporarily banned on this server."

# The A7 baseline: its as-run plan, its Files listing and its transfer.
A7_ACTIONS = 29  # the actions of the as-run plan
A7_FILES = 41  # the entries of the Files listing reply
A7_TRANSFER_BYTES = 1049073  # the FILP length, and the transfer size in the ACK
A7_FILE_SIZE = 1048893  # the logical file size in the ACK
FILE_KIND_FIELD = 205  # the file-info field that the baseline names "Text File"

# The option-one ban request and the frames around it.
BAN_REQUEST_TYPE = 110  # the request that carries the option-one ban
BAN_REQUEST_ID = 33  # the identifier of that request and of its ACK
UID_BYTES = 2  # a user identifier is two bytes
USER_LEFT_ID = 4  # the identifier of the 302 notification after the ACK
PROBE_COMPLETED_ACTIONS = 2  # the probe's actions before its timeout


def need(
    condition: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers pass the check positionally
    reason: str,
) -> None:
    """Keep a check active even when Python runs with optimization enabled.

    Parameters
    ----------
    condition : bool
        The check that must hold.
    reason : str
        The message of the error that a failed check raises.

    Raises
    ------
    ValueError
        With ``reason``, when ``condition`` is false.
    """
    if not condition:
        raise ValueError(reason)


def digest(path: Path) -> str:
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


def loaded(path: Path) -> Report:
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


def frame(report: Report, connection: str, identifier: int) -> Report:
    """Return the one reply of a connection with a given identifier.

    Parameters
    ----------
    report : dict[str, typing.Any]
        A verified capture report.
    connection : str
        The connection whose reply is wanted.
    identifier : int
        The transaction identifier of the reply.

    Returns
    -------
    dict[str, typing.Any]
        The single matching reply frame.
    """
    matches = [
        item
        for item in report["frames"]
        if item["connection"] == connection
        and item["is_reply"] == 1
        and item["id"] == identifier
    ]
    need(len(matches) == 1, f"Reply {connection}/{identifier} missing or repeated")
    return matches[0]


def fields(item: Report) -> dict[int, bytes]:
    """Return the fields of a frame keyed by their identifiers.

    Parameters
    ----------
    item : dict[str, typing.Any]
        A decoded frame with its ``fields`` list.

    Returns
    -------
    dict[int, bytes]
        The raw bytes of each field.
    """
    return {entry["id"]: bytes.fromhex(entry["hex"]) for entry in item["fields"]}
