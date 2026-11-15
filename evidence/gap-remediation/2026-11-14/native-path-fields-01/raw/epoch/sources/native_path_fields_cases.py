#!/usr/bin/env python3
"""Produce twelve exact, field-specific native path observations."""

import argparse
import hashlib
import json
from pathlib import Path

from native_folder_cases import path
from native_plan import packet, payload
from protocol_capture import ORACLE_SHA256

PORT = 15900
FILES = b"m-path47"
SOURCE = path((FILES, b"S"))
WRAPPER = path((FILES,))
HIGH = path((FILES, b"H-\x9a"))
FILES_ROOT = b"\0\0"
NEWS = b"m-n47-\x9a"
CATEGORY = b"m-cat47"
NEWS_HIGH = path((NEWS,))
NEWS_CATEGORY = path((NEWS, CATEGORY))
P212 = bytes.fromhex("00020000086d2d706174683437000003482d9a")
P325 = bytes.fromhex("00010000076d2d6e34372d9a")
HELLO = "54525450484f544c00010002"
HELLO_REPLY = "5452545000000000"
MUTATIONS = {204, 205, 208, 380, 381, 382}
REQUIRED_ENV = (
    "fixture_profile",
    "emulator_pid",
    "emulator_starttime",
    "emulator_sha256",
    "emulator_netns_inode",
    "owned_working_image",
    "owned_working_image_inode",
)


def sha(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def cells() -> list[dict]:
    values = [
        (212, P212),
        (212, bytes.fromhex("00030000086d2d706174683437000003482d9a000000")),
        (212, bytes.fromhex("00030000086d2d706174683437000003482d9a")),
        (212, bytes.fromhex("00020000086d2d706174683437ffff03482d9a")),
        (212, P212 + b"\xee" * 2029),
        (212, P212 + b"\xee" * 2030),
        (325, P325),
        (325, bytes.fromhex("00020000076d2d6e34372d9a000000")),
        (325, bytes.fromhex("00020000076d2d6e34372d9a")),
        (325, bytes.fromhex("0001ffff076d2d6e34372d9a")),
        (325, P325 + b"\xee" * 2036),
        (325, P325 + b"\xee" * 2037),
    ]
    assert [len(v) for _, v in values] == [
        19,
        22,
        19,
        19,
        2048,
        2049,
        12,
        15,
        12,
        12,
        2048,
        2049,
    ]
    return [
        {
            "index": i,
            "field": field,
            "value_hex": value.hex(),
            "declared_count": int.from_bytes(value[:2], "big"),
            "bytes": len(value),
            "marker_hex": (b"p" + bytes([48 + i])).hex() if i < 6 else None,
        }
        for i, (field, value) in enumerate(values)
    ]


def request(
    label: str,
    kind: int,
    identifier: int,
    values: list[tuple[int, bytes]] | None,
    phase: str,
    *,
    marker: bytes | None = None,
) -> dict:
    return {
        "label": label,
        "phase": phase,
        "kind": kind,
        "id": identifier,
        "fields": None
        if values is None
        else [[field, raw.hex()] for field, raw in values],
        "marker_hex": None if marker is None else marker.hex(),
        "mutation": kind in MUTATIONS,
    }


def raw_request(spec: dict, dynamic_parent: bytes | None = None) -> str:
    values = spec["fields"]
    if values is None:
        if dynamic_parent is None or spec["kind"] != 206:
            raise ValueError("Dynamic parent unresolved or wrong operation")
        values = [[201, spec["marker_hex"]], [202, dynamic_parent.hex()]]
    return packet(
        spec["kind"],
        spec["id"],
        payload([(int(field), bytes.fromhex(str(raw))) for field, raw in values]),
    )


def source_plan(environment: dict, port: int = PORT) -> dict:
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError("Only isolated control-only 15900 profile is prepared")
    if any(not environment.get(key) for key in REQUIRED_ENV):
        raise ValueError("Incomplete runtime identity")
    specs: list[dict] = []
    next_id = 100

    def add(
        label: str,
        kind: int,
        values: list[tuple[int, bytes]] | None,
        phase: str,
        marker: bytes | None = None,
    ) -> None:
        nonlocal next_id
        specs.append(request(label, kind, next_id, values, phase, marker=marker))
        next_id += 1

    for label, kind, values in [
        ("initial-accounts", 348, []),
        ("initial-roster", 300, []),
        ("initial-files-root", 200, [(202, FILES_ROOT)]),
        ("initial-news-root", 370, [(325, FILES_ROOT)]),
    ]:
        add(label, kind, values, "initial")
    for name, parent in [
        (FILES, FILES_ROOT),
        (b"S", WRAPPER),
        (b"H-\x9a", WRAPPER),
        *[(b"p" + bytes([48 + i]), SOURCE) for i in range(6)],
    ]:
        add("create-files-" + name.hex(), 205, [(201, name), (202, parent)], "setup")
    add("create-news-folder", 381, [(201, NEWS)], "setup")
    add("create-news-category", 382, [(322, CATEGORY), (325, NEWS_HIGH)], "setup")
    for label, parent in [("S", SOURCE), ("wrapper", WRAPPER), ("H", HIGH)]:
        add("setup-view-" + label, 200, [(202, parent)], "setup-view")
    add("setup-news-high", 370, [(325, NEWS_HIGH)], "setup-view")
    for i, cell in enumerate(cells()[:6]):
        marker = bytes.fromhex(cell["marker_hex"])
        phase = f"files-{i}"
        add(f"before-info-{i}", 206, [(201, marker), (202, SOURCE)], phase)
        add(
            f"move-{i}",
            208,
            [(201, marker), (202, SOURCE), (212, bytes.fromhex(cell["value_hex"]))],
            phase,
            marker,
        )
        for label, parent in [("S", SOURCE), ("wrapper", WRAPPER), ("H", HIGH)]:
            add(f"after-view-{i}-{label}", 200, [(202, parent)], phase)
        add(f"after-info-{i}", 206, None, phase, marker)
        add(f"barrier-files-{i}", 500, [], phase)
    for i, cell in enumerate(cells()[6:], 6):
        add(f"news-{i}", 370, [(325, bytes.fromhex(cell["value_hex"]))], f"news-{i}")
        add(f"barrier-news-{i}", 500, [], f"news-{i}")
    add("remove-news-category", 380, [(325, NEWS_CATEGORY)], "cleanup")
    add("remove-news-folder", 380, [(325, NEWS_HIGH)], "cleanup")
    add("remove-files-wrapper", 204, [(201, FILES), (202, FILES_ROOT)], "cleanup")
    for label, kind, values in [
        ("final-accounts", 348, []),
        ("final-roster", 300, []),
        ("final-files-root", 200, [(202, FILES_ROOT)]),
        ("final-news-root", 370, [(325, FILES_ROOT)]),
        ("final-barrier", 500, []),
    ]:
        add(label, kind, values, "final")
    assert len(specs) == 81 and sum(s["mutation"] for s in specs) == 20
    assert len({s["id"] for s in specs}) == 81
    return {
        "schema_version": 1,
        "gap_id": "GAP-047",
        "profile": "native-mac-oracle",
        "oracle_sha256": ORACLE_SHA256,
        "environment": environment,
        "endpoint": {"host": "127.0.0.1", "port": port},
        "hello": HELLO,
        "hello_reply": HELLO_REPLY,
        "preflight": "separate unchanged closed 18-action control readiness",
        "requests": specs,
        "cells": cells(),
        "case_request_count_with_login": 82,
        "mutation_count": 20,
        "limits": {
            "case_seconds": 210,
            "epoch_seconds": 720,
            "start_margin_seconds": 390,
            "max_requests_per_connection": 99,
            "max_extra_readonly": 17,
            "max_frames": 400,
            "max_bytes": 8 * 1024 * 1024,
            "max_tail_bytes": 65536,
        },
        "unproved": [
            "field equivalence",
            "native error statuses",
            "location from ACK",
            "stopped catalogue identity",
        ],
    }


def write_plan(output: Path, environment: dict, port: int = PORT) -> str:
    value = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    (output / "source-hashes.json").write_text(
        json.dumps(
            {
                "plan.json": sha(raw),
                "native_path_fields_cases.py": sha(Path(__file__).read_bytes()),
                "native_path_fields_control.py": sha(
                    Path(__file__)
                    .with_name("native_path_fields_control.py")
                    .read_bytes()
                ),
            },
            indent=2,
        )
        + "\n"
    )
    return sha(raw)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--runtime", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--port", type=int, default=PORT)
    args = parser.parse_args()
    print(write_plan(args.output, json.loads(args.runtime.read_text()), args.port))


if __name__ == "__main__":
    main()
