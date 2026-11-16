#!/usr/bin/env python3
"""Produce twelve exact, field-specific native path observations."""

import hashlib
import json
import sys
from pathlib import Path

from native_folder_cases import path
from native_plan import packet, payload
from native_wire_names import TYPE_GET_FILE_INFO
from protocol_capture import ORACLE_SHA256
from script_cli import run

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
# The plan holds this many requests, from the first login to the final barrier.
REQUEST_COUNT = 81
# This many of those requests change the server.
MUTATION_COUNT = 20
# The identifier of the first request; each later request takes the next one.
FIRST_ID = 100
# The first six cells move a file; the other six are news folders.
FILE_CELLS = 6
# The byte lengths that the twelve tested values must have.
CELL_LENGTHS = [19, 22, 19, 19, 2048, 2049, 12, 15, 12, 12, 2048, 2049]
# The three views of the folder tree that the case reads after each move.
VIEWS = (("S", SOURCE), ("wrapper", WRAPPER), ("H", HIGH))
# The message of the error for a runtime that is not the control-only profile.
PROFILE_MESSAGE = "Only isolated control-only 15900 profile is prepared"
# The message of the error for a runtime record that lacks a required field.
IDENTITY_MESSAGE = "Incomplete runtime identity"
# The message of the error for a request whose parent cannot be resolved.
PARENT_MESSAGE = "Dynamic parent unresolved or wrong operation"
# One planned request: label, kind, field values, phase and optional marker.
type Step = tuple[str, int, list[tuple[int, bytes]] | None, str, bytes | None]


def sha(raw: bytes) -> str:
    """Return the SHA-256 hexadecimal digest of some bytes.

    Returns
    -------
    str
        The digest in hexadecimal.
    """
    return hashlib.sha256(raw).hexdigest()


def cells() -> list[dict]:
    """Build the twelve tested values and the facts that describe each.

    Returns
    -------
    list[dict]
        One description per cell, in the order the case tests them.
    """
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
    assert [len(v) for _, v in values] == CELL_LENGTHS, "cell lengths differ"  # ruff: ignore[assert]  # fixed by the case
    return [
        {
            "index": i,
            "field": field,
            "value_hex": value.hex(),
            "declared_count": int.from_bytes(value[:2], "big"),
            "bytes": len(value),
            "marker_hex": (b"p" + bytes([48 + i])).hex() if i < FILE_CELLS else None,
        }
        for i, (field, value) in enumerate(values)
    ]


def request(  # ruff: ignore[too-many-arguments, too-many-positional-arguments]  # the planner's callers pass these in this order  # pylint: disable=too-many-arguments,too-many-positional-arguments  # as above
    label: str,
    kind: int,
    identifier: int,
    values: list[tuple[int, bytes]] | None,
    phase: str,
    *,
    marker: bytes | None = None,
) -> dict:
    """Describe one request of the case as the plan records it.

    Returns
    -------
    dict
        The plan entry for the request.
    """
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
    """Encode one planned request as the packet that the case sends.

    Returns
    -------
    str
        The encoded packet in hexadecimal.

    Raises
    ------
    ValueError
        If the request needs a dynamic parent that was not supplied, or is not
        the information request that takes one.
    """
    values = spec["fields"]
    if values is None:
        if dynamic_parent is None or spec["kind"] != TYPE_GET_FILE_INFO:
            raise ValueError(PARENT_MESSAGE)
        values = [[201, spec["marker_hex"]], [202, dynamic_parent.hex()]]
    return packet(
        spec["kind"],
        spec["id"],
        payload([(int(field), bytes.fromhex(str(raw))) for field, raw in values]),
    )


def _opening_steps() -> list[Step]:
    """Plan the login, the setup and the views that precede the cells.

    Returns
    -------
    list[Step]
        The steps that precede the cells, in the order they are sent.
    """
    steps: list[Step] = [
        (label, kind, values, "initial", None)
        for label, kind, values in [
            ("initial-accounts", 348, []),
            ("initial-roster", 300, []),
            ("initial-files-root", 200, [(202, FILES_ROOT)]),
            ("initial-news-root", 370, [(325, FILES_ROOT)]),
        ]
    ]
    steps.extend(
        (
            "create-files-" + name.hex(),
            205,
            [(201, name), (202, parent)],
            "setup",
            None,
        )
        for name, parent in [
            (FILES, FILES_ROOT),
            (b"S", WRAPPER),
            (b"H-\x9a", WRAPPER),
            *[(b"p" + bytes([48 + i]), SOURCE) for i in range(6)],
        ]
    )
    steps.extend([
        ("create-news-folder", 381, [(201, NEWS)], "setup", None),
        (
            "create-news-category",
            382,
            [(322, CATEGORY), (325, NEWS_HIGH)],
            "setup",
            None,
        ),
    ])
    steps.extend(
        (f"setup-view-{label}", 200, [(202, parent)], "setup-view", None)
        for label, parent in VIEWS
    )
    steps.append(("setup-news-high", 370, [(325, NEWS_HIGH)], "setup-view", None))
    return steps


def _cell_steps() -> list[Step]:
    """Plan the move and the reads of every tested cell.

    Returns
    -------
    list[Step]
        The steps of the file cells, then of the news cells.
    """
    tested = cells()
    steps: list[Step] = []
    for index, cell in enumerate(tested[:FILE_CELLS]):
        marker = bytes.fromhex(cell["marker_hex"])
        value = bytes.fromhex(cell["value_hex"])
        phase = f"files-{index}"
        views = [
            (f"after-view-{index}-{label}", 200, [(202, parent)], phase, None)
            for label, parent in VIEWS
        ]
        steps.extend([
            (f"before-info-{index}", 206, [(201, marker), (202, SOURCE)], phase, None),
            (
                f"move-{index}",
                208,
                [(201, marker), (202, SOURCE), (212, value)],
                phase,
                marker,
            ),
            *views,
            (f"after-info-{index}", 206, None, phase, marker),
            (f"barrier-files-{index}", 500, [], phase, None),
        ])
    for index, cell in enumerate(tested[FILE_CELLS:], FILE_CELLS):
        phase = f"news-{index}"
        steps.extend([
            (
                f"news-{index}",
                370,
                [(325, bytes.fromhex(cell["value_hex"]))],
                phase,
                None,
            ),
            (f"barrier-news-{index}", 500, [], phase, None),
        ])
    return steps


def _closing_steps() -> list[Step]:
    """Plan the cleanup and the final reads of the case.

    Returns
    -------
    list[Step]
        The cleanup steps, then the final reads.
    """
    steps: list[Step] = [
        ("remove-news-category", 380, [(325, NEWS_CATEGORY)], "cleanup", None),
        ("remove-news-folder", 380, [(325, NEWS_HIGH)], "cleanup", None),
        (
            "remove-files-wrapper",
            204,
            [(201, FILES), (202, FILES_ROOT)],
            "cleanup",
            None,
        ),
    ]
    steps.extend(
        (label, kind, values, "final", None)
        for label, kind, values in [
            ("final-accounts", 348, []),
            ("final-roster", 300, []),
            ("final-files-root", 200, [(202, FILES_ROOT)]),
            ("final-news-root", 370, [(325, FILES_ROOT)]),
            ("final-barrier", 500, []),
        ]
    )
    return steps


def source_plan(environment: dict, port: int = PORT) -> dict:
    """Plan the case for an isolated control-only runtime.

    Returns
    -------
    dict
        The complete plan, with the requests, the cells and the limits.

    Raises
    ------
    ValueError
        If the port or profile is not the prepared one, or if the runtime
        identity is incomplete.
    """
    if port != PORT or environment.get("fixture_profile") != "control-only":
        raise ValueError(PROFILE_MESSAGE)
    if any(not environment.get(key) for key in REQUIRED_ENV):
        raise ValueError(IDENTITY_MESSAGE)
    steps = _opening_steps() + _cell_steps() + _closing_steps()
    specs = [
        request(label, kind, FIRST_ID + index, values, phase, marker=marker)
        for index, (label, kind, values, phase, marker) in enumerate(steps)
    ]
    assert (  # ruff: ignore[assert]  # the counts are fixed by the case, checked once
        len(specs),
        sum(s["mutation"] for s in specs),
        len({s["id"] for s in specs}),
    ) == (REQUEST_COUNT, MUTATION_COUNT, REQUEST_COUNT), "request counts differ"
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
    """Write the plan and the hashes of its sources into a new directory.

    Returns
    -------
    str
        The SHA-256 digest of the plan file.
    """
    value = source_plan(environment, port)
    output.mkdir(parents=True, exist_ok=False)
    raw = (json.dumps(value, indent=2) + "\n").encode()
    (output / "plan.json").write_bytes(raw)
    here = Path(__file__)
    (output / "source-hashes.json").write_text(
        json.dumps(
            {
                "plan.json": sha(raw),
                "native_path_fields_cases.py": sha(here.read_bytes()),
                "native_path_fields_control.py": sha(
                    here.with_name("native_path_fields_control.py").read_bytes()
                ),
            },
            indent=2,
        )
        + "\n"
    )
    return sha(raw)


def cli(*, runtime: str, output: str, port: int = PORT) -> None:
    """Write the plan for a runtime record and print the digest of the plan."""
    runtime_value = json.loads(Path(runtime).read_text(encoding="utf-8"))
    digest = write_plan(Path(output), runtime_value, port)
    sys.stdout.write(digest + "\n")


def main() -> None:
    """Generate the native path-fields plan from the command line."""
    run(cli, __doc__)


if __name__ == "__main__":
    main()
