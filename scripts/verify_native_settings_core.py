"""Share the constants and readers of the settings corpus checks."""

import hashlib
import typing as typ

from verify_native_core import require

type Report = dict[str, typ.Any]

ORACLE_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
DATA_SHA = "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"
RSRC_SHA = "40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5"
FIELD_DIGESTS = {
    10: "9b50231527d14140c07f7a690db3f7feecf8428fb6181f3ee3711cbcfc2da958",
    11: "452607103fd8119ca4a71e733f62ebba8d7baa1f8da8962f753da24d877c0f1d",
    12: "1895a4d463c2be43ef6eb77fea5466fa47aaf82726138dee7a3c4a2da8c253a0",
    14: "ee9f3964d4dbfca175a3d9bbca42222f370dab0f92d51ae3ebeed3b0b12be56b",
}


def sha(data: bytes) -> str:
    """Hash bytes.

    Returns
    -------
    str
        The lower-case hexadecimal SHA-256.
    """
    return hashlib.sha256(data).hexdigest()


def reply(report: Report, identifier: int) -> Report:
    """Find the one successful reply to a request of the A7 baseline.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The capture report.
    identifier : int
        The request identifier.

    Returns
    -------
    dict[str, typing.Any]
        The reply frame.
    """
    found = [
        f for f in report["frames"] if f["is_reply"] == 1 and f["id"] == identifier
    ]
    require(
        len(found) == 1 and found[0]["error"] == 0, f"A7 reply {identifier} missing"
    )
    return found[0]


def values(frame: Report) -> dict[int, bytes]:
    """Map the field IDs of a decoded frame to their values.

    Returns
    -------
    dict[int, bytes]
        Each field's bytes, by ID.
    """
    return {f["id"]: bytes.fromhex(f["hex"]) for f in frame["fields"]}
