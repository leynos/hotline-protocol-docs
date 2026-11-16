"""Check the C53 retirement and the C55 boot of the isolated control witness."""

import typing as typ

from pcap_tcp import read_packets
from verify_native_ban_control_core import (
    CONTROL_PORT,
    EXPECTED,
    NS,
    PCAP_HEADER_BYTES,
    PID,
    START,
    Json,
    digest,
    loaded,
    need,
)

if typ.TYPE_CHECKING:
    from pathlib import Path

READY_PURPOSE = "control-only boot readiness; full_file_baseline=not_exercised"
MIN_RECORDER_SECONDS = 360  # the recorders must outlast the case
UNPRIVILEGED_UID = "1000"
CAPABILITIES = "0000000000020000"  # the emulator's effective capabilities
LAB_PORTS = (CONTROL_PORT, CONTROL_PORT + 1, CONTROL_PORT + 2, CONTROL_PORT + 3)
NO_ROUTES = ""  # the namespace has no route out
PCAP_MAGIC_HEX = "d4c3b2a1"  # a little-endian classic capture file


def retirement(corpus: Path) -> None:
    """Check that the C53 emulator retired without contact.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    """
    old = loaded(corpus / "boot-c53/terminal.json")
    need(
        old["actual_pid_gone"] is True
        and old["primary_syn_pcap_bytes"] == PCAP_HEADER_BYTES
        and old["namespace_pcap_bytes"] == PCAP_HEADER_BYTES,
        "C53 no-contact retirement differs",
    )
    for label in ("primary-syn", "lab-namespace"):
        need(
            not read_packets(corpus / "boot-c53" / f"{label}.pcap"),
            "C53 no-contact capture has packets",
        )


def emulator_identity(ready: Json) -> None:
    """Check the readiness record's purpose and the emulator's identity.

    Parameters
    ----------
    ready : dict[str, typing.Any]
        The C55 readiness record.
    """
    emulator = ready["actual_emulator"]
    need(
        ready["purpose"] == READY_PURPOSE
        and ready["no_frontend_contact"] is True
        and ready["root_controller_required_for_case"] is True
        and (emulator["pid"], emulator["starttime"], emulator["netns"])
        == (PID, START, NS)
        and emulator["uid"].split()[1] == UNPRIVILEGED_UID
        and emulator["cap_eff"].split()[1] == CAPABILITIES
        and emulator["fd6"].endswith("native-eventlab-one-01/working.dsk")
        and emulator["fd16"].endswith("native-ban-control-c55/lab-guest.pcap")
        and emulator["exe"].endswith(EXPECTED["emulator"]),
        "Boot emulator identity differs",
    )


def source_hashes(ready: Json) -> None:
    """Check the hashes of the sources that the emulator booted from.

    Parameters
    ----------
    ready : dict[str, typing.Any]
        The C55 readiness record.
    """
    source = ready["source_hashes"]
    need(
        source
        == {
            "base": EXPECTED["base"],
            "rom": EXPECTED["rom"],
            "emulator": EXPECTED["emulator"],
            "server_data": EXPECTED["data"],
            "server_rsrc": EXPECTED["rsrc"],
        },
        "Preboot source hashes differ",
    )


def isolation(ready: Json) -> None:
    """Check the recorders' remaining time, the namespace and the listeners.

    Parameters
    ----------
    ready : dict[str, typing.Any]
        The C55 readiness record.
    """
    need(
        ready["recorder_remaining_seconds"]["host"] >= MIN_RECORDER_SECONDS
        and ready["recorder_remaining_seconds"]["namespace"] >= MIN_RECORDER_SECONDS
        and ready["namespace"]["routes"] == NO_ROUTES
        and all(
            f"127.0.0.1:{port}" in ready["namespace"]["listeners"] for port in LAB_PORTS
        )
        and ready["primary_syn_pcap_bytes"] == PCAP_HEADER_BYTES,
        "Boot recorder deadline, isolation or listener differs",
    )


def recorders(corpus: Path, ready: Json) -> None:
    """Check the boot screenshot and each managed recorder's final witness.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.
    ready : dict[str, typing.Any]
        The C55 readiness record.
    """
    need(
        digest(corpus / "boot-c55/server-ready.png") == ready["screenshot_sha256"],
        "Boot screenshot identity differs",
    )
    for label in ("host", "namespace"):
        witness = loaded(corpus / "boot-c55" / f"{label}-ready-final.json")
        need(
            witness == ready["recorders"][label]
            and witness["unit_properties"]["ActiveState"] == "active"
            and witness["unit_properties"]["KillMode"] == "control-group"
            and witness["header24"].startswith(PCAP_MAGIC_HEX)
            and witness["deadline_utc"] == ready["case_deadline_utc"],
            f"{label} managed recorder differs",
        )


def boot(corpus: Path) -> Json:
    """Check the C53 retirement and the C55 boot readiness.

    Parameters
    ----------
    corpus : pathlib.Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The C55 readiness record.
    """
    retirement(corpus)
    ready = loaded(corpus / "boot-c55/readiness.json")
    emulator_identity(ready)
    source_hashes(ready)
    isolation(ready)
    recorders(corpus, ready)
    return ready
