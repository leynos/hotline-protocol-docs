#!/usr/bin/env python3
"""Verify portable synthetic proxy rehearsal and zero-contact receipts offline."""

import hashlib
import json
import struct
import typing as typ
from pathlib import Path

from native_wire_names import TYPE_LOGIN_AGREEMENT
from script_cli import run

SOURCE_SHA256 = "44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e"
HELLO = bytes.fromhex("54525450484f544c00010002")
ANSWER = bytes.fromhex("5452545000000000")
MIN_FRAME_BYTES = 22  # the 20-byte header and the field count
PCAP_HEADER_BYTES = 24  # the global header of a classic PCAP file
CUTOFF_NS = 28_000_000_000  # the watchdog's cutoff, 28 seconds after the ACK
TEARDOWN_LIMIT_NS = 30_000_000_000  # the most that teardown may take after the ACK
TIMING_TOLERANCE = 1e-9  # the agreement allowed between two recorded durations
A7_ACTIONS = 29  # the completed actions that the A7 check records


def need(
    ok: bool,  # ruff: ignore[boolean-type-hint-positional-argument]  # the callers' shape
) -> None:
    """Fail without a message when a check does not hold.

    Raises
    ------
    AssertionError
        When ``ok`` is false.
    """
    if not ok:
        raise AssertionError


def load(path: Path) -> dict[str, typ.Any]:
    """Read one JSON document.

    Parameters
    ----------
    path : Path
        The file to read.

    Returns
    -------
    dict[str, typing.Any]
        The parsed document.
    """
    return json.loads(path.read_text())


def check_inventory(root: Path) -> None:
    """Check every file of the corpus against the inventory of its checksums.

    Parameters
    ----------
    root : Path
        The corpus directory, which holds ``SHA256SUMS``.
    """
    inventory = root / "SHA256SUMS"
    need(inventory.is_file())
    base = root.parents[3]
    listed: set[Path] = set()
    for line in inventory.read_text().splitlines():
        digest, relative = line.split("  ", 1)
        path = (base / relative).resolve()
        need(path.is_relative_to(root.resolve()) and path != inventory.resolve())
        need(path not in listed and path.is_file())
        need(hashlib.sha256(path.read_bytes()).hexdigest() == digest)
        listed.add(path)
    actual = {path.resolve() for path in root.rglob("*") if path.is_file()}
    need(listed == actual - {inventory.resolve()})


def frame(raw_hex: str) -> tuple[int, int, int, int, list[tuple[int, bytes]]]:
    """Split one wire frame into its header words and its fields.

    Parameters
    ----------
    raw_hex : str
        The frame in hexadecimal.

    Returns
    -------
    tuple[int, int, int, int, list[tuple[int, bytes]]]
        The reply flag, the type, the identifier, the error and the fields.
    """
    raw = bytes.fromhex(raw_hex)
    need(len(raw) >= MIN_FRAME_BYTES)
    _, reply, kind, identifier, error, total, size = struct.unpack(">BBHIIII", raw[:20])
    need(total == size == len(raw) - 20)
    return reply, kind, identifier, error, split_fields(raw[20:])


def split_fields(body: bytes) -> list[tuple[int, bytes]]:
    """Split the body of a frame into its counted fields.

    Parameters
    ----------
    body : bytes
        The frame after its 20-byte header.

    Returns
    -------
    list[tuple[int, bytes]]
        The field identifier and value of each field, in order.
    """
    count = int.from_bytes(body[:2], "big")
    fields = []
    cursor = 2
    for _ in range(count):
        need(cursor + 4 <= len(body))
        field_id, length = struct.unpack(">HH", body[cursor : cursor + 4])
        cursor += 4
        need(cursor + length <= len(body))
        fields.append((field_id, body[cursor : cursor + length]))
        cursor += length
    need(cursor == len(body))
    return fields


def check_manifest(manifest: dict[str, typ.Any]) -> None:
    """Check the claims that the manifest makes about the rehearsal.

    Parameters
    ----------
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    need(manifest["schema_version"] == 1)
    need(manifest["synthetic_rehearsal_only"] is True)
    need(manifest["native_peer_evidence"] is False)
    need(manifest["classic_baseline_connected"] is False)
    need(manifest["classic_field_tolerance_proved"] is False)


def check_source(root: Path, manifest: dict[str, typ.Any]) -> None:
    """Check the frozen proxy source against its recorded hash.

    Parameters
    ----------
    root : Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    source = root / "source/classic_login_proxy.py.txt"
    need(hashlib.sha256(source.read_bytes()).hexdigest() == SOURCE_SHA256)
    need(manifest["source_sha256"] == SOURCE_SHA256)


def check_ready(
    ready: dict[str, typ.Any],
    runner: dict[str, typ.Any],
    manifest: dict[str, typ.Any],
) -> None:
    """Check the readiness receipt against the runner and the manifest.

    Parameters
    ----------
    ready : dict[str, typing.Any]
        The parsed ``ready.json``.
    runner : dict[str, typing.Any]
        The parsed ``runner.json``.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    need(ready["status"] == "ready" and ready["variant"] == "baseline")
    need(ready["netns_inode"] == runner["events"][0]["namespace_inode"])
    need(ready["netns_inode"] == manifest["b29"]["fresh_netns_inode"])
    need(
        ready["netns_inode"]
        not in {
            manifest["b29"]["host_netns_inode"],
            manifest["b29"]["actual_client_netns_inode"],
        }
    )
    need(ready["routes"] == {"control": 15500, "data": 15501})
    need(ready["listeners"] == {"control": 15652, "data": 15653})
    need(runner["events"][0]["interfaces"] == ["lo"])
    need(manifest["b29"]["native_server_contact"] is False)
    need(manifest["b29"]["guest_emulator_contact"] is False)


def check_run(
    runner: dict[str, typ.Any],
    report: dict[str, typ.Any],
    summary: dict[str, typ.Any],
    receipt: dict[str, typ.Any],
) -> None:
    """Check that the run ended cleanly and that the cutoff fired.

    Parameters
    ----------
    runner : dict[str, typing.Any]
        The parsed ``runner.json``.
    report : dict[str, typing.Any]
        The parsed proxy report.
    summary : dict[str, typing.Any]
        The parsed ``summary.json``.
    receipt : dict[str, typing.Any]
        The watchdog receipt, which is ``report["observation"]``.
    """
    need(runner["failures"] == [] and report["errors"] == [])
    need(report["status"] == summary["status"] == "intentional-observation-cutoff")
    need(receipt["state"] == "fired" and receipt["error"] is None)


def check_timing(receipt: dict[str, typ.Any], summary: dict[str, typ.Any]) -> int:
    """Check the order and the length of the cutoff and teardown timestamps.

    Parameters
    ----------
    receipt : dict[str, typing.Any]
        The watchdog receipt, which is ``report["observation"]``.
    summary : dict[str, typing.Any]
        The parsed ``summary.json``.

    Returns
    -------
    int
        The nanoseconds from the ACK to the relay teardown.
    """
    ack_time = receipt["ack_sent_monotonic_ns"]
    need(receipt["cutoff_due_ns"] - ack_time == CUTOFF_NS)
    need(ack_time <= receipt["cutoff_due_ns"] <= receipt["cutoff_actual_ns"])
    need(receipt["cutoff_actual_ns"] <= receipt["last_owned_socket_close_ns"])
    need(receipt["last_owned_socket_close_ns"] <= receipt["relay_teardown_ns"])
    elapsed = receipt["relay_teardown_ns"] - ack_time
    need(CUTOFF_NS <= elapsed <= TEARDOWN_LIMIT_NS)
    need(receipt["valid_30_seconds"] is True)
    need(abs(summary["ack_to_teardown_seconds"] - elapsed / 1e9) < TIMING_TOLERANCE)
    need(summary["proxy_pid_gone"] is True)
    return elapsed


def check_runner(runner: dict[str, typ.Any]) -> None:
    """Check the proxy's process identity and exit in the runner's events.

    Parameters
    ----------
    runner : dict[str, typing.Any]
        The parsed ``runner.json``.
    """
    need(runner["events"][1]["proxy_pid"] == runner["events"][-1]["final_proxy_pid"])
    need(runner["events"][-1]["final_exit"] == 0)
    need(runner["events"][1]["proxy_argv"][2:4] == ["--variant", "baseline"])


def check_units(root: Path) -> None:
    """Check that the proxy unit was stopped and held no network namespace.

    Parameters
    ----------
    root : Path
        The corpus directory.
    """
    final = (root / "synthetic/unit-final-before-stop.txt").read_text()
    need("MainPID=0" in final)
    need("PrivateNetwork=yes" in final)
    stopped = (root / "synthetic/unit-stopped.txt").read_text()
    need("ActiveState=inactive" in stopped)
    need("MainPID=0" in stopped)


def check_entries(report: dict[str, typ.Any], receipt: dict[str, typ.Any]) -> None:
    """Check the audited frames of the rehearsal and their acknowledgement digests.

    Parameters
    ----------
    report : dict[str, typing.Any]
        The parsed proxy report.
    receipt : dict[str, typing.Any]
        The watchdog receipt, which is ``report["observation"]``.
    """
    entries = report["entries"]
    need(
        [entry["event"] for entry in entries]
        == [
            "client-handshake",
            "server-handshake",
            "login-request",
            "server",
            "server",
            "data-client",
            "data-server",
        ]
    )
    need(all(entry["raw_hex"] == entry["forwarded_hex"] for entry in entries))
    need(bytes.fromhex(entries[0]["raw_hex"]) == HELLO)
    need(bytes.fromhex(entries[1]["raw_hex"]) == ANSWER)
    login = frame(entries[2]["raw_hex"])
    ack = frame(entries[3]["raw_hex"])
    notice = frame(entries[4]["raw_hex"])
    need(login[:2] == (0, 107) and login[3] == 0)
    need(ack[:4] == (1, 0, login[2], 0))
    need(ack[4] == [(161, b"\0\0")])
    need(notice[1] == TYPE_LOGIN_AGREEMENT and notice[3] == 0)
    need(bytes.fromhex(entries[5]["raw_hex"]) == b"PING")
    need(bytes.fromhex(entries[6]["raw_hex"]) == b"PONG")
    need(receipt["raw_ack_sha256"] == receipt["forwarded_ack_sha256"])
    need(
        receipt["raw_ack_sha256"]
        == hashlib.sha256(bytes.fromhex(entries[3]["raw_hex"])).hexdigest()
    )


def check_batches(root: Path, manifest: dict[str, typ.Any]) -> None:
    """Check the zero-contact batches that never connected to a peer.

    Parameters
    ----------
    root : Path
        The corpus directory.
    manifest : dict[str, typing.Any]
        The parsed ``manifest.json``.
    """
    for batch in ("b30", "b31"):
        need(manifest[batch]["native_or_classic_proxy_connection"] is False)
        for view in ("host", "namespace"):
            raw = (root / batch / f"{view}.pcap").read_bytes()
            need(len(raw) == PCAP_HEADER_BYTES and raw[:4] == bytes.fromhex("d4c3b2a1"))
        outcome = load(root / batch / "outcome.json")
        need(
            outcome["host_pcap_bytes"]
            == outcome["namespace_pcap_bytes"]
            == PCAP_HEADER_BYTES
        )
        need(load(root / batch / "a7-check.json")["completed_actions"] == A7_ACTIONS)
    need(load(root / "b30/outcome.json")["client_connect_clicks"] == 0)
    need("Result=timeout" in (root / "b30/proxy-unit-failed.txt").read_text())
    need(load(root / "b31/outcome.json")["connect_clicks"] == 1)
    need(
        load(root / "b31/outcome.json")["client_dialog_still_open_after_click"] is True
    )
    need(
        load(root / "b31/connect-action-log.json")["ambient_modifier_state"]
        == "not independently measured"
    )
    need("MainPID=0" in (root / "b31/proxy-unit-stopped.txt").read_text())


def verify(root: Path) -> dict[str, typ.Any]:
    """Verify the synthetic rehearsal corpus and its zero-contact receipts.

    Parameters
    ----------
    root : Path
        The corpus directory.

    Returns
    -------
    dict[str, typing.Any]
        The verdict and the ACK-to-teardown interval in seconds.
    """
    root = root.resolve()
    check_inventory(root)
    manifest = load(root / "manifest.json")
    check_manifest(manifest)
    check_source(root, manifest)
    ready = load(root / "synthetic/ready.json")
    report = load(root / "synthetic/report.json")
    runner = load(root / "synthetic/runner.json")
    summary = load(root / "synthetic/summary.json")
    receipt = report["observation"]
    check_ready(ready, runner, manifest)
    check_run(runner, report, summary, receipt)
    elapsed = check_timing(receipt, summary)
    check_runner(runner)
    check_units(root)
    check_entries(report, receipt)
    check_batches(root, manifest)
    return {
        "status": "verified-synthetic-and-zero-contact",
        "elapsed_seconds": elapsed / 1e9,
    }


def show(corpus: str) -> None:
    """Verify a rehearsal corpus and print its summary as JSON.

    Parameters
    ----------
    corpus : str
        The corpus directory.
    """
    print(json.dumps(verify(Path(corpus)), sort_keys=True))


def main() -> None:
    """Verify a synthetic proxy rehearsal corpus from the command line."""
    run(show, __doc__)


if __name__ == "__main__":
    main()
