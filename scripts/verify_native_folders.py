#!/usr/bin/env python3
"""Verify native folder state transitions, item streams and filesystem effects."""

import argparse
import hashlib
import json
from pathlib import Path

from native_filp import decode
from native_folder_cases import FILES, ORDER, downloads, skip_all, upload_fresh
from native_folder_clock_checks import download_clock, upload_clock
from native_folder_files import verify_files
from native_folder_stream import download, upload
from native_folder_timing import uploads as timed_uploads
from native_folder_upload_cases import (
    catalogue_flush,
    empty_uploads,
    partial_seed,
    resumed_uploads,
)
from native_packet_evidence import reconcile
from native_transfer_cases import file_stream, resource_fork
from pcap_tcp import read_packets, stream
from protocol_capture import verify_capture
from verify_native_cleanup import flow
from verify_native_core import require
from verify_native_forks import check_file_info, check_metadata, fields
from verify_native_framing import check_quiet


def response(report: dict, identifier: int = 10) -> dict:
    frames = [
        f
        for f in report["frames"]
        if f["connection"] == "a" and f["is_reply"] and f["id"] == identifier
    ]
    require(len(frames) == 1, "Missing folder request ACK")
    return frames[0]


def summarize(items: list[dict]) -> list[dict]:
    return [
        {
            "path": b"/".join(item["path"]).decode("ascii"),
            "directory": item["directory"],
            "action": item["action"],
            "stream_size": item.get("stream_size"),
            "received_body_bytes": len(item.get("body", b"")),
            "complete": item.get("complete", True),
            "next_ready": item.get("next_ready"),
        }
        for item in items
    ]


def check_download(name: str, report: dict, packets: dict) -> dict:
    values = fields(response(report))
    if name == "folder-download-empty":
        require(
            set(values) == {108, 220}
            and values[108] == b"\0\0"
            and values[220] == b"\0\0",
            "Empty folder allocated a transfer",
        )
        require(
            set(report["streams"]) == {"a"}, "Empty folder opened a data connection"
        )
        return {"items": [], "aggregate_bytes": 0, "item_count": 0}
    require(
        len(values[107]) == 4 and int.from_bytes(values[107], "big") & 1 != 0,
        "Folder download reference differs",
    )
    recorded = report["streams"]["folder"]
    sent, received = (
        bytes.fromhex(recorded["sent_hex"]),
        bytes.fromhex(recorded["received_hex"]),
    )
    require(sent[4:8] == values[107], "Folder HTXF reference differs")
    parsed = download(sent, received)
    items = parsed["items"]
    expected_order = (
        [(True, (b"only",))] if name == "folder-download-dir-only" else ORDER
    )
    require(
        [(i["directory"], i["path"]) for i in items] == expected_order,
        "Folder traversal order/path differs",
    )
    require(
        all(not any(i["words"]) for i in items),
        "Native descriptor component word changed",
    )
    count = int.from_bytes(values[220], "big")
    size = int.from_bytes(values[108], "big")
    require(
        count == len(items)
        and size == (0 if name == "folder-download-dir-only" else 652),
        "Folder aggregate/count differs",
    )
    require(
        packets["folder"]["guest_server_initiated_close"],
        "Folder traversal did not close natively",
    )
    for item in items:
        if item["directory"]:
            continue
        path = item["path"]
        should_skip = name == "folder-download-skip-all" or (
            name == "folder-download-mixed" and path == (b"alpha",)
        )
        if should_skip:
            require(
                item["action"] == "skip" and "body" not in item,
                "Skipped file delivered a body",
            )
            continue
        expected_data, expected_resource = FILES[path]
        resume = name == "folder-download-resume" or (
            name == "folder-download-mixed" and path == (b"inner", b"leaf")
        )
        require(
            item["action"] == ("resume" if resume else "fresh"),
            "Folder file choice differs",
        )
        if resume:
            offsets = [
                (b"DATA", 0 if path == (b"zero",) else 3),
                (b"MACR", 0 if path == (b"zero",) else 4),
            ]
            require(item["rflt"] == offsets, "Folder download resume offsets differ")
            expected_data, expected_resource = (
                expected_data[offsets[0][1] :],
                expected_resource[offsets[1][1] :],
            )
        forks = decode(item["body"])
        require(
            forks["DATA"] == expected_data and forks["MACR"] == expected_resource,
            "Folder download fork bytes differ",
        )
        check_metadata(forks["INFO"], path[-1], False)
    require(
        parsed["ignored"]
        == (
            [{"state": 0, "control": 0}, {"state": 1, "control": 0}]
            if name == "folder-download-unknown-control"
            else []
        ),
        "Unexpected folder control handling",
    )
    return {
        "items": summarize(items),
        "aggregate_bytes": size,
        "item_count": count,
        "file_stream_bytes": sum(len(i.get("body", b"")) for i in items),
        "ignored": parsed["ignored"],
    }


def check_upload(name: str, report: dict, packets: dict) -> dict:
    values = fields(response(report))
    if name == "folder-upload-zero-items":
        require(
            not values and set(report["streams"]) == {"a"},
            "Zero-item upload allocated a reference",
        )
        return {"items": [], "completed_items": 0}
    require(
        set(values) == {107}
        and len(values[107]) == 4
        and not int.from_bytes(values[107], "big") & 1,
        "Folder upload ACK differs",
    )
    recorded = report["streams"]["folder"]
    sent, received = (
        bytes.fromhex(recorded["sent_hex"]),
        bytes.fromhex(recorded["received_hex"]),
    )
    require(sent[4:8] == values[107], "Folder upload reference differs")
    parsed = upload(sent, received)
    items = parsed["items"]
    expected_paths = {
        "folder-upload-fresh": [
            (b"empty",),
            (b"inner",),
            (b"alpha",),
            (b"zero",),
            (b"inner", b"leaf"),
        ],
        "folder-upload-directory-last": [(b"only",)],
        "folder-upload-partial-seed": [(b"alpha",), (b"part",)],
        "folder-upload-resume": [(b"alpha",), (b"part",), (b"finish",)],
        "folder-upload-completed-skip": [(b"alpha",)],
        "folder-upload-directory-conflict": [(b"alpha",)],
    }[name]
    require([i["path"] for i in items] == expected_paths, "Folder upload paths differ")
    expected_directories = {
        "folder-upload-fresh": [True, True, False, False, False],
        "folder-upload-directory-last": [True],
        "folder-upload-partial-seed": [False, False],
        "folder-upload-resume": [False, False, True],
        "folder-upload-completed-skip": [False],
        "folder-upload-directory-conflict": [True],
    }[name]
    require(
        [i["flags"] for i in items] == [int(v) for v in expected_directories],
        "Folder upload item flags differ",
    )
    expected_controls = {
        "folder-upload-fresh": [3, 3, 1, 1, 1],
        "folder-upload-directory-last": [3],
        "folder-upload-partial-seed": [1, 1],
        "folder-upload-resume": [3, 2, 3],
        "folder-upload-completed-skip": [3],
        "folder-upload-directory-conflict": [3],
    }[name]
    require(
        [i["control"] for i in items] == expected_controls,
        "Folder upload choice sequence differs",
    )
    for index, item in enumerate(items):
        require(not any(item["words"]), "Unexpected upload component word")
        if "body" not in item:
            continue
        if not item["complete"]:
            require(
                name == "folder-upload-partial-seed"
                and item["stream_size"] == 509
                and item["body"] == file_stream(*FILES[(b"alpha",)])[:-312],
                "Partial folder stream differs",
            )
            continue
        forks = decode(item["body"])
        expected = (
            FILES[item["path"]] if name == "folder-upload-fresh" else FILES[(b"alpha",)]
        )
        if item["control"] == 2:
            require(
                item["rflt"] == [(b"DATA", 13), (b"MACR", 5)],
                "Folder upload resume negotiation differs",
            )
            expected = (b"", resource_fork()[5:])
        require(
            (forks["DATA"], forks["MACR"]) == expected,
            "Folder upload fork bytes differ",
        )
        check_metadata(forks["INFO"], item["path"][-1], True)
        require(
            item["next_ready"] == (index < len(items) - 1),
            "File-ending next-control differs",
        )
    partial = name == "folder-upload-partial-seed"
    require(
        packets["folder"]["guest_server_initiated_close"] != partial,
        "Folder completion/interruption close differs",
    )
    if partial:
        require(parsed["completed"] == 1, "Partial item was counted complete")
        check_file_info(response(report, 11), b"alpha", 330)
        info = fields(response(report, 12))
        require(
            info[213] == b"HTft" and int.from_bytes(info[207], "big") == 18,
            "Partial file-info state differs",
        )
    else:
        require(
            parsed["completed"] == len(items), "Folder processed-item count differs"
        )
    return {
        "items": summarize(items),
        "completed_items": parsed["completed"],
        "final_item_kind": "directory-or-skip" if items[-1]["control"] == 3 else "file",
    }


def verify(directory: Path) -> dict:
    host, guest = (
        read_packets(directory / "host.pcap"),
        read_packets(directory / "guest.pcap"),
    )
    expected = (
        upload_fresh()
        | skip_all()
        | empty_uploads()
        | partial_seed()
        | downloads()
        | resumed_uploads()
        | timed_uploads()
    )
    require(
        {p.name for p in (directory / "transcripts").iterdir()} == set(expected),
        "Folder corpus inventory differs",
    )
    source_hashes = {
        hashlib.sha256(p.read_bytes()).hexdigest()
        for p in (directory / "sources").glob("protocol_capture*.txt")
    }
    unread = json.loads((directory / "unread-output.json").read_text())
    observations = []
    timer_host, timer_guest = (
        read_packets(directory / "timers-host.pcap"),
        read_packets(directory / "timers-guest.pcap"),
    )
    for name, (steps, expectation) in expected.items():
        case = directory / "transcripts" / name
        report = verify_capture(case)
        plan = json.loads((case / "plan.json").read_text())
        require(
            report["status"] == "completed"
            and report["driver_sha256"] in source_hashes,
            "Incomplete folder capture or missing source",
        )
        require(
            plan["steps"] == steps and plan["expectation"] == expectation,
            "Folder plan differs",
        )
        require(
            str(case.relative_to(directory)) not in unread,
            "Unexpected final unread output",
        )
        timed = name in timed_uploads() or name == "folder-download-delayed-choice"
        case_host, case_guest = (timer_host, timer_guest) if timed else (host, guest)
        packets = reconcile(report, case_host, case_guest)
        check_quiet(report, plan)
        if name in timed_uploads():
            require(
                packets["folder"]["guest_server_initiated_close"],
                "Timed folder did not close natively",
            )
            outcome = upload_clock(name, report, plan, case_guest)
        else:
            outcome = (
                check_download(name, report, packets)
                if name.startswith("folder-download-")
                else check_upload(name, report, packets)
            )
            if name == "folder-download-delayed-choice":
                outcome.update(download_clock(report, plan, case_guest))
        observations.append({"case": name, "connections": packets, **outcome})
    native_files = verify_files(directory)
    initial = []
    differences = json.loads(
        (directory / "initial-boundary-differences.json").read_text()
    )
    require(
        len(differences) == 1 and differences[0]["guest_input_hex"] == "",
        "Initial boundary difference changed",
    )
    for path in sorted((directory / "initial-probes").rglob("report.json")):
        report = verify_capture(path.parent)
        require(
            report["driver_sha256"] in source_hashes,
            "Missing initial folder capture source",
        )
        name = str(path.parent.relative_to(directory))
        if name == differences[0]["case"]:
            require(
                report["status"] == "failed" and not report["frames"],
                "Boundary-different probe reached folder protocol",
            )
            connect = report["events"][0]
            packets, client, endpoint = flow(report, connect["connection"], guest)
            require(
                stream(packets, client, endpoint).hex()
                == differences[0]["guest_input_hex"]
                and stream(packets, endpoint, client).hex()
                == differences[0]["guest_output_hex"],
                "Guest failed-admission bytes differ",
            )
            host_client, host_endpoint = (
                tuple(connect["local_address"]),
                tuple(connect["peer_address"]),
            )
            # This observed tuple was not reused in the bounded host corpus.
            require(
                stream(host, host_client, host_endpoint).hex()
                == report["streams"]["a"]["sent_hex"]
                == differences[0]["host_sent_hex"],
                "Host failed-admission bytes differ",
            )
            require(
                stream(host, host_endpoint, host_client).hex()
                == report["streams"]["a"]["received_hex"]
                == differences[0]["host_received_hex"]
                == "",
                "Unexpected host failed-admission output",
            )
        else:
            reconcile(
                report,
                host,
                guest,
                {k: bytes.fromhex(v) for k, v in unread.get(name, {}).items()},
            )
        initial.append(
            {"case": name, "status": report["status"], "error": report["error"]}
        )
    require(
        len(initial) == 3 and sum(i["status"] == "failed" for i in initial) == 2,
        "Initial folder probe inventory differs",
    )
    auxiliary = verify_capture(directory / "auxiliary/folder-catalogue-flush")
    require(
        auxiliary["status"] == "completed"
        and auxiliary["driver_sha256"] in source_hashes,
        "Auxiliary finalization failed or source missing",
    )
    aux_plan = json.loads(
        (directory / "auxiliary/folder-catalogue-flush/plan.json").read_text()
    )
    aux_steps, aux_expectation = catalogue_flush()["folder-catalogue-flush"]
    require(
        aux_plan["steps"] == aux_steps and aux_plan["expectation"] == aux_expectation,
        "Auxiliary plan differs",
    )
    aux_packets = reconcile(auxiliary, host, guest)
    aux_values = fields(response(auxiliary))
    aux_sent = bytes.fromhex(auxiliary["streams"]["upload"]["sent_hex"])
    require(
        aux_sent[:8] == b"HTXF" + aux_values[107]
        and int.from_bytes(aux_sent[8:12], "big") == len(aux_sent) - 16,
        "Auxiliary upload header differs",
    )
    aux_forks = decode(aux_sent[16:])
    require(
        not aux_forks["DATA"]
        and not aux_forks["MACR"]
        and aux_packets["upload"]["guest_server_initiated_close"],
        "Auxiliary finalization bytes/close differ",
    )
    return {
        "cases": observations,
        "native_files": native_files,
        "initial_probes": initial,
        "auxiliary_captures": 1,
        "scope": "Fourteen final direction-specific folder cases; positive direct catalogue states, not exhaustive listing or restart-durability proof; admission failures excluded from folder semantics",
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path)
    args = parser.parse_args()
    print(json.dumps(verify(args.directory), indent=2))


if __name__ == "__main__":
    main()
