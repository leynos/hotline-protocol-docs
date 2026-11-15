#!/usr/bin/env python3
"""Verify portable synthetic proxy rehearsal and zero-contact receipts offline."""

import argparse
import hashlib
import json
import struct
from pathlib import Path

SOURCE_SHA256 = "44bb68fe0bc464874aa455e823ca08b00704b88f5064d776119fcaf0682a5c7e"
HELLO = bytes.fromhex("54525450484f544c00010002")
ANSWER = bytes.fromhex("5452545000000000")


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def check_inventory(root: Path) -> None:
    inventory = root / "SHA256SUMS"
    assert inventory.is_file()
    base = root.parents[3]
    listed: set[Path] = set()
    for line in inventory.read_text().splitlines():
        digest, relative = line.split("  ", 1)
        path = (base / relative).resolve()
        assert path.is_relative_to(root.resolve()) and path != inventory.resolve()
        assert path not in listed and path.is_file()
        assert hashlib.sha256(path.read_bytes()).hexdigest() == digest
        listed.add(path)
    actual = {path.resolve() for path in root.rglob("*") if path.is_file()}
    assert listed == actual - {inventory.resolve()}


def frame(raw_hex: str) -> tuple[int, int, int, int, list[tuple[int, bytes]]]:
    raw = bytes.fromhex(raw_hex)
    assert len(raw) >= 22
    _, reply, kind, identifier, error, total, size = struct.unpack(">BBHIIII", raw[:20])
    assert total == size == len(raw) - 20
    body = raw[20:]
    count = int.from_bytes(body[:2], "big")
    fields = []
    cursor = 2
    for _ in range(count):
        assert cursor + 4 <= len(body)
        field_id, length = struct.unpack(">HH", body[cursor : cursor + 4])
        cursor += 4
        assert cursor + length <= len(body)
        fields.append((field_id, body[cursor : cursor + length]))
        cursor += length
    assert cursor == len(body)
    return reply, kind, identifier, error, fields


def verify(root: Path) -> dict:
    root = root.resolve()
    check_inventory(root)
    manifest = load(root / "manifest.json")
    assert manifest["schema_version"] == 1
    assert manifest["synthetic_rehearsal_only"] is True
    assert manifest["native_peer_evidence"] is False
    assert manifest["classic_baseline_connected"] is False
    assert manifest["classic_field_tolerance_proved"] is False
    source = root / "source/classic_login_proxy.py.txt"
    assert hashlib.sha256(source.read_bytes()).hexdigest() == SOURCE_SHA256
    assert manifest["source_sha256"] == SOURCE_SHA256

    ready = load(root / "synthetic/ready.json")
    report = load(root / "synthetic/report.json")
    runner = load(root / "synthetic/runner.json")
    summary = load(root / "synthetic/summary.json")
    receipt = report["observation"]
    assert ready["status"] == "ready" and ready["variant"] == "baseline"
    assert ready["netns_inode"] == runner["events"][0]["namespace_inode"]
    assert ready["netns_inode"] == manifest["b29"]["fresh_netns_inode"]
    assert ready["netns_inode"] not in (
        manifest["b29"]["host_netns_inode"],
        manifest["b29"]["actual_client_netns_inode"],
    )
    assert ready["routes"] == {"control": 15500, "data": 15501}
    assert ready["listeners"] == {"control": 15652, "data": 15653}
    assert runner["events"][0]["interfaces"] == ["lo"]
    assert manifest["b29"]["native_server_contact"] is False
    assert manifest["b29"]["guest_emulator_contact"] is False
    assert runner["failures"] == [] and report["errors"] == []
    assert report["status"] == summary["status"] == "intentional-observation-cutoff"
    assert receipt["state"] == "fired" and receipt["error"] is None
    ack_time = receipt["ack_sent_monotonic_ns"]
    assert receipt["cutoff_due_ns"] - ack_time == 28_000_000_000
    assert ack_time <= receipt["cutoff_due_ns"] <= receipt["cutoff_actual_ns"]
    assert receipt["cutoff_actual_ns"] <= receipt["last_owned_socket_close_ns"]
    assert receipt["last_owned_socket_close_ns"] <= receipt["relay_teardown_ns"]
    elapsed = receipt["relay_teardown_ns"] - ack_time
    assert 28_000_000_000 <= elapsed <= 30_000_000_000
    assert receipt["valid_30_seconds"] is True
    assert abs(summary["ack_to_teardown_seconds"] - elapsed / 1e9) < 1e-9
    assert summary["proxy_pid_gone"] is True
    assert runner["events"][1]["proxy_pid"] == runner["events"][-1]["final_proxy_pid"]
    assert runner["events"][-1]["final_exit"] == 0
    assert runner["events"][1]["proxy_argv"][2:4] == ["--variant", "baseline"]
    assert "MainPID=0" in (root / "synthetic/unit-final-before-stop.txt").read_text()
    assert (
        "PrivateNetwork=yes"
        in (root / "synthetic/unit-final-before-stop.txt").read_text()
    )
    assert "ActiveState=inactive" in (root / "synthetic/unit-stopped.txt").read_text()
    assert "MainPID=0" in (root / "synthetic/unit-stopped.txt").read_text()

    entries = report["entries"]
    assert [entry["event"] for entry in entries] == [
        "client-handshake",
        "server-handshake",
        "login-request",
        "server",
        "server",
        "data-client",
        "data-server",
    ]
    assert all(entry["raw_hex"] == entry["forwarded_hex"] for entry in entries)
    assert bytes.fromhex(entries[0]["raw_hex"]) == HELLO
    assert bytes.fromhex(entries[1]["raw_hex"]) == ANSWER
    login = frame(entries[2]["raw_hex"])
    ack = frame(entries[3]["raw_hex"])
    notice = frame(entries[4]["raw_hex"])
    assert login[:2] == (0, 107) and login[3] == 0
    assert ack[:4] == (1, 0, login[2], 0)
    assert ack[4] == [(161, b"\0\0")]
    assert notice[1] == 109 and notice[3] == 0
    assert bytes.fromhex(entries[5]["raw_hex"]) == b"PING"
    assert bytes.fromhex(entries[6]["raw_hex"]) == b"PONG"
    assert receipt["raw_ack_sha256"] == receipt["forwarded_ack_sha256"]
    assert (
        receipt["raw_ack_sha256"]
        == hashlib.sha256(bytes.fromhex(entries[3]["raw_hex"])).hexdigest()
    )

    for batch in ("b30", "b31"):
        assert manifest[batch]["native_or_classic_proxy_connection"] is False
        for view in ("host", "namespace"):
            raw = (root / batch / f"{view}.pcap").read_bytes()
            assert len(raw) == 24 and raw[:4] == bytes.fromhex("d4c3b2a1")
        outcome = load(root / batch / "outcome.json")
        assert outcome["host_pcap_bytes"] == outcome["namespace_pcap_bytes"] == 24
        assert load(root / batch / "a7-check.json")["completed_actions"] == 29
    assert load(root / "b30/outcome.json")["client_connect_clicks"] == 0
    assert "Result=timeout" in (root / "b30/proxy-unit-failed.txt").read_text()
    assert load(root / "b31/outcome.json")["connect_clicks"] == 1
    assert (
        load(root / "b31/outcome.json")["client_dialog_still_open_after_click"] is True
    )
    assert (
        load(root / "b31/connect-action-log.json")["ambient_modifier_state"]
        == "not independently measured"
    )
    assert "MainPID=0" in (root / "b31/proxy-unit-stopped.txt").read_text()
    return {
        "status": "verified-synthetic-and-zero-contact",
        "elapsed_seconds": elapsed / 1e9,
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.corpus), sort_keys=True))


if __name__ == "__main__":
    main()
