"""Check the immutable A7 baseline plan that the private-message planners extend."""

import hashlib
import json
import typing as typ

from protocol_capture import ORACLE_SHA256, validate_plan

type Json = dict[str, typ.Any]

BASELINE_SHA256 = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
FULL_STREAM_BYTES = 1049073
BASELINE_STEPS = 29
DOWNLOAD_CONNECT_STEP = 19
DOWNLOAD_READ_STEP = 21
DOWNLOAD_EOF_STEP = 24
CONTROL_PORT = 15500
DATA_PORT = 15501
EXPECTED_DATA_SHA256 = (
    "fbbab289f7f94b25736c58be46a994c441fd02552cc6022352e3d86d2fab7c83"
)
EXPECTED_RSRC_SHA256 = (
    "40a42dbcf2d879e22d9a5a9acf46bf15fa9fe3a77837f757a990e514436801e5"
)
BASELINE_ENDPOINTS = {
    "control": {"host": "127.0.0.1", "port": CONTROL_PORT},
    "data": {"host": "127.0.0.1", "port": DATA_PORT},
}
BASELINE_DOWNLOAD_STEP = {
    "op": "connect",
    "connection": "download",
    "endpoint": "data",
    "timeout": 10,
}
BASELINE_EXPECTATION = {
    "case": "existing-fixture-full-readback",
    "name_hex": b"mothra-race-fixture".hex(),
    "expected_stream_bytes": FULL_STREAM_BYTES,
    "expected_data_sha256": EXPECTED_DATA_SHA256,
    "expected_rsrc_sha256": EXPECTED_RSRC_SHA256,
}
IDENTITY_KEYS = ("oracle_sha256", "emulator_pid", "emulator_sha256", "guest_pcap")


def check_baseline_structure(plan: Json) -> None:
    """Check that a plan is the A7 baseline's full-readback shape.

    The checks run in a fixed order, so the first failure decides the error:
    the capture validator, the oracle identity, the expectation, the step count
    and endpoints, and the download sequence.

    Parameters
    ----------
    plan : dict[str, typing.Any]
        The parsed baseline plan.

    Raises
    ------
    ValueError
        If any check fails.
    """
    validate_plan(plan)
    if plan["profile"] != "native-mac-oracle" or plan["oracle_sha256"] != ORACLE_SHA256:
        message = "A7 baseline oracle identity differs"
        raise ValueError(message)
    if plan["expectation"] != BASELINE_EXPECTATION:
        message = "A7 baseline full-fork expectation differs"
        raise ValueError(message)
    steps = plan["steps"]
    if len(steps) != BASELINE_STEPS or plan["endpoints"] != BASELINE_ENDPOINTS:
        message = "A7 baseline full 29-step/data-endpoint shape differs"
        raise ValueError(message)
    if steps[DOWNLOAD_CONNECT_STEP] != BASELINE_DOWNLOAD_STEP:
        message = "A7 baseline full download sequence differs"
        raise ValueError(message)
    if steps[DOWNLOAD_READ_STEP].get("size") != FULL_STREAM_BYTES:
        message = "A7 baseline full download sequence differs"
        raise ValueError(message)
    if steps[DOWNLOAD_EOF_STEP]["op"] != "read_eof":
        message = "A7 baseline full download sequence differs"
        raise ValueError(message)


def load_baseline(raw: bytes) -> Json:
    """Parse the baseline plan once its bytes are known to be the recorded ones.

    Parameters
    ----------
    raw : bytes
        The baseline plan's bytes.

    Returns
    -------
    dict[str, typing.Any]
        The parsed plan.

    Raises
    ------
    ValueError
        If the bytes hash to another value, or the plan fails
        :func:`check_baseline_structure`.
    """
    if hashlib.sha256(raw).hexdigest() != BASELINE_SHA256:
        message = "A7 baseline input SHA-256 differs"
        raise ValueError(message)
    plan = json.loads(raw)
    check_baseline_structure(plan)
    return plan
