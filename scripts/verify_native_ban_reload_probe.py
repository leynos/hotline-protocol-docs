"""Check the one fresh-login probe of the persisted-ban reload witness."""

import typing as typ

from capture_acceptance import driver_is
from native_control_readiness import probe
from native_wire_names import HANDSHAKE_REPLY_HEX, HANDSHAKE_REQUEST_HEX
from protocol_capture import verify_capture
from verify_native_ban_reload_core import (
    DATA,
    PID,
    PREPARED,
    PROBE_STEPS,
    read,
    require,
    sha,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

type Report = dict[str, typ.Any]

# The header of a fresh Login107 frame: type 107, identifier 1.
LOGIN_FRAME_PREFIX_HEX = "0000006b00000001"
# The type word 110 of a frame header, which the probe must never send.
BAN_REQUEST_TYPE_HEX = "0000006e"


def check_probe(corpus: Path, ready: Report) -> Report:
    """Check the one-probe vector, its launch and its capture, then replay the probe.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    ready : dict[str, typing.Any]
        The parsed ``ui-ready.json``, which the probe does not use.

    Returns
    -------
    dict[str, typing.Any]
        The verified capture report of the probe.
    """
    root = corpus / "c61"
    prepared = read(root / "probe-prepared.json")
    asrun = read(root / "probe-asrun.json")
    launch = read(root / "probe-launch.json")
    require(
        sha(root / "probe-prepared.json") == launch["prepared_sha256"] == PREPARED
        and sha(root / "probe-asrun.json") == launch["asrun_sha256"]
        and launch["steps_unchanged"] is True
        and prepared["steps"] == asrun["steps"]
        and prepared["environment"] == asrun["environment"]
        and prepared["endpoints"] == asrun["endpoints"]
        and asrun["gap_ids"] == ["GAP-044", "GAP-074"]
        and len(asrun["steps"]) == PROBE_STEPS
        and asrun["environment"]["emulator_pid"] == PID
        and asrun["environment"]["fixture_profile"] == "persisted-ban-reload-readonly"
        and asrun["environment"]["full_file_baseline"] == "not_exercised"
        and asrun["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15750}},
        "Prepared/as-run one-probe vector differs",
    )
    steps = asrun["steps"]
    require(
        [s["op"] for s in steps]
        == ["connect", "send", "read", "send", "read_frame", "close"]
        and steps[1]["hex"] == HANDSHAKE_REQUEST_HEX
        and steps[2]["expect_hex"] == HANDSHAKE_REPLY_HEX
        and steps[3]["hex"].startswith(LOGIN_FRAME_PREFIX_HEX)
        and steps[4]["match_frame"] == {"is_reply": 1, "id": 1}
        and not any(BAN_REQUEST_TYPE_HEX in s.get("hex", "") for s in steps),
        "Fresh TRTP/107 vector or no-110 scope differs",
    )
    argv = launch["argv"]
    require(
        "--property=User=0" in argv
        and "--property=Group=0" in argv
        and f"--property=NetworkNamespacePath=/proc/{PID}/ns/net" in argv
        and "--property=RuntimeMaxSec=60" in argv
        and "--property=Type=oneshot" in argv
        and "--property=RemainAfterExit=yes" in argv
        and argv[argv.index("capture") + 1].endswith("probe-asrun.json")
        and read(root / "probe-launch-result.json")["returncode"] == 0
        and "completed; 6 actions" in (root / "probe-unit.log").read_text(),
        "Managed root/namespace probe or exit differs",
    )
    require(
        sha(root / "probe-asrun.json") == sha(root / "probe-capture/plan.json"),
        "Captured plan differs from as-run vector",
    )
    report = verify_capture(root / "probe-capture")
    require(
        report["status"] == "completed"
        and report["completed_actions"] == PROBE_STEPS
        and report["oracle_sha256"] == DATA
        and driver_is(report, sha(corpus / "sources/protocol_capture.py"))
        and report["profile"] == "native-mac-oracle",
        "One-probe capture incomplete",
    )
    probe(report)
    return report
