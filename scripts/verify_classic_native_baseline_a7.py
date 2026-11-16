"""Replay the two A7 action captures that accompany a Classic/native baseline case."""

import json
import typing as typ

from native_filp import decode as decode_filp
from verify_classic_native_baseline_common import (
    ACCOUNT_COUNT,
    AGREEMENT_SHA,
    DATA_SHA,
    FILE_COUNT,
    FILP_BYTES,
    FILP_SHA,
    REPLAY_ACTIONS,
    RSRC_SHA,
    STATIC_ACTIONS,
    digest,
    require,
)

if typ.TYPE_CHECKING:
    from pathlib import Path


def verify_a7(directory: Path) -> dict[str, typ.Any]:
    """Check the preflight and postflight A7 replays of one case.

    Returns
    -------
    dict[str, typing.Any]
        The action, account and file counts, and the FILP digest.
    """
    pre = json.loads((directory / "a7-preflight/report.json").read_text())
    post = json.loads((directory / "a7-postflight/report.json").read_text())
    require(
        all(
            x["status"] == "completed" and x["completed_actions"] == REPLAY_ACTIONS
            for x in (pre, post)
        ),
        "A7 action completion",
    )
    require(
        pre["oracle_sha256"]
        == post["oracle_sha256"]
        == "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
        "Native oracle identity",
    )
    for r in (pre, post):
        frames = {f["action"]: f for f in r["frames"]}
        filp = bytes.fromhex(r["streams"]["download"]["received_hex"])
        require(
            len(frames[8]["fields"]) == ACCOUNT_COUNT
            and len(frames[10]["fields"]) == FILE_COUNT,
            "A7 accounts/Files",
        )
        require(
            len(filp) == FILP_BYTES and digest(filp) == FILP_SHA,
            "Full FILP incl both forks",
        )
        forks = decode_filp(filp)
        require(digest(forks["DATA"]) == DATA_SHA, "A7 data fork")
        require(digest(forks["MACR"]) == RSRC_SHA, "A7 resource fork")
        require(
            digest(bytes.fromhex(frames[6]["fields"][0]["hex"])) == AGREEMENT_SHA,
            "A7 agreement",
        )
    pf = {f["action"]: f for f in pre["frames"]}
    qf = {f["action"]: f for f in post["frames"]}
    require(all(pf[i] == qf[i] for i in STATIC_ACTIONS), "A7 static frame drift")
    return {
        "actions_each": REPLAY_ACTIONS,
        "accounts": ACCOUNT_COUNT,
        "files": FILE_COUNT,
        "filp_sha256": FILP_SHA,
    }
