#!/usr/bin/env python3
"""Run and independently check one bounded native 212/325 path matrix."""

import argparse
import hashlib
import json
import os
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import native_path_fields_cases as cases
from native_ban_expiry_control import runtime_gate, utc
from native_news_decode import categories
from native_plan import login
from native_rate304_control import Wire as RateWire
from protocol_capture import ORACLE_SHA256, decode_frame
from verify_native_account_updates import enumeration
from verify_native_auth import ADMIN, roster
from verify_native_mkdir import listing
from verify_native_shx import fields

AGREEMENT_SHA = "5288d060a4270cf6ae899302c52b2ac784b30dea99f01d2d4cd1c1037c4bd1c7"
PARENTS = {"S": cases.SOURCE, "wrapper": cases.WRAPPER, "H": cases.HIGH}
MARKERS = {b"p" + bytes([48 + i]) for i in range(6)}


class Wire(RateWire):
    """Bounded transport with path-matrix progress retained on failure."""

    request_count: int = 0
    partial: dict


def need(ok: bool, message: str) -> None:
    """Raise a value error with the message unless the condition holds."""
    if not ok:
        raise ValueError(message)


def sha(raw: bytes) -> str:
    """Return the SHA-256 hex digest of the bytes."""
    return hashlib.sha256(raw).hexdigest()


def prepared(directory: Path) -> dict:
    """Check the prepared plan against its source hashes and the source plan and return it."""
    raw = (directory / "plan.json").read_bytes()
    expected = {
        "plan.json": sha(raw),
        "native_path_fields_cases.py": sha(Path(cases.__file__).read_bytes()),
        "native_path_fields_control.py": sha(Path(__file__).read_bytes()),
    }
    need(
        json.loads((directory / "source-hashes.json").read_text()) == expected,
        "Prepared plan or source hash differs",
    )
    plan = json.loads(raw)
    need(
        plan == cases.source_plan(plan["environment"], plan["endpoint"]["port"]),
        "Prepared plan differs from source",
    )
    return plan


def one(frames: list[dict], connection: str, identifier: int) -> dict:
    """Return the single direct reply with the given identifier on a connection."""
    result = [
        f
        for f in frames
        if f["connection"] == connection
        and f["type"] == 0
        and f["is_reply"] == 1
        and f["id"] == identifier
    ]
    need(len(result) == 1, f"Missing/duplicate direct reply {connection}/{identifier}")
    return result[0]


def exact_fields(frame: dict) -> dict[int, bytes]:
    """Return a frame's fields, refusing malformed, fragmented or repeated ones."""
    values = fields(frame)
    need(
        frame["flags"] == 0
        and frame["total_size"] == frame["data_size"]
        and frame.get("declared_field_count") == len(frame["fields"])
        and len(values) == len(frame["fields"])
        and frame.get("unconsumed_hex") == "",
        "Malformed/fragmented/repeated scalar frame",
    )
    return values


def success(frame: dict) -> None:
    """Require a direct successful reply."""
    need(
        frame["flags"] == 0
        and frame["is_reply"] == 1
        and frame["type"] == 0
        and frame["error"] == 0,
        "Expected direct success",
    )


def login_gate(frames: list[dict], connection: str) -> None:
    """Check a connection's login reply, administrator grant and agreement."""
    ack = one(frames, connection, 1)
    success(ack)
    need(
        exact_fields(ack) == {160: b"\0\xbe", 161: b"\0\0"},
        "Login version/extras differ",
    )
    grants = [f for f in frames if f["connection"] == connection and f["type"] == 354]
    agreements = [
        f for f in frames if f["connection"] == connection and f["type"] == 109
    ]
    need(
        len(grants) == len(agreements) == 1
        and exact_fields(grants[0]) == {110: ADMIN}
        and sha(exact_fields(agreements[0]).get(101, b"")) == AGREEMENT_SHA,
        "Admin grant/agreement differs",
    )


def file_view(frame: dict) -> list[str]:
    """Return the names in a file list reply as hexadecimal text."""
    return [name.hex() for name in listing(frame)]


def file_types(frame: dict) -> dict[str, str]:
    """Return the type and creator bytes of each entry in a file list reply, by name."""
    return {name.hex(): record[:8].hex() for name, record in listing(frame).items()}


def news_view(frame: dict) -> list[dict]:
    """Return the field, kind and name of each entry in a news listing reply."""
    return [
        {"field": row["field"], "kind": row["kind"], "name_hex": row["name"].hex()}
        for row in categories(frame)
    ]


def file_info(frame: dict, marker: bytes) -> dict:
    """Check the information reply for the owned marker folder and describe it."""
    success(frame)
    data = exact_fields(frame)
    need(
        data.get(201) == marker and data.get(213) == b"fldr",
        "Owned marker206 name/kind differs",
    )
    return {
        "field_ids": sorted(data),
        "name_hex": marker.hex(),
        "raw_sha256": sha(bytes.fromhex(frame["raw_hex"])),
    }


def check_names(actual: list[str], expected: set[bytes], label: str) -> None:
    """Require a listing to hold exactly the expected owned names."""
    need(
        set(actual) == {name.hex() for name in expected}
        and len(actual) == len(expected),
        f"{label} owned listing differs",
    )


def location(views: dict[str, list[str]], marker: bytes) -> str | None:
    """Return the one parent whose listing holds the marker, or none."""
    found = [parent for parent, names in views.items() if marker.hex() in names]
    need(len(found) <= 1, "Marker appears in multiple selected parents")
    return found[0] if found else None


def exact_transition(
    before: dict[str, list[str]],
    after: dict[str, list[str]],
    marker: bytes,
    found: str,
    before_types: dict[str, dict[str, str]],
    after_types: dict[str, dict[str, str]],
) -> None:
    """Only this marker may change parent; keep every other name and duplicate."""
    need(set(before) == set(after) == set(PARENTS), "Incomplete parent views")
    previous = location(before, marker)
    need(previous == "S", "Marker was not uniquely in source")
    for parent in PARENTS:
        expected = Counter(before[parent])
        if parent == "S":
            expected[marker.hex()] -= 1
            if expected[marker.hex()] == 0:
                del expected[marker.hex()]
        if parent == found:
            expected[marker.hex()] += 1
        need(
            Counter(after[parent]) == expected,
            "Unexpected name or duplicate in owned parent",
        )
        expected_types = dict(before_types[parent])
        if parent == "S":
            marker_type = expected_types.pop(marker.hex())
        if parent == found:
            expected_types[marker.hex()] = marker_type
        need(
            after_types[parent] == expected_types,
            "Unchanged owned file type or creator differs",
        )


def classify_views(plan: dict, report: dict) -> None:
    """Classify only measured selected parents; never derive a move from ACK."""
    records = report["views"]
    by_label = {v["label"]: v for v in records}
    need(len(by_label) == len(records), "Duplicate view label")
    pre_files = by_label["initial-files-root"]["names"]
    pre_news = by_label["initial-news-root"]["names"]
    need(
        cases.FILES.hex() not in pre_files
        and cases.NEWS.hex() not in {v["name_hex"] for v in pre_news},
        "Owned names preexist",
    )
    initial_accounts = by_label["initial-accounts"]["accounts"]
    need(
        len(initial_accounts) == 2
        and by_label["final-accounts"]["accounts"] == initial_accounts,
        "Original accounts differ",
    )
    own_uid = by_label["initial-roster"]["uid"]
    need(
        1 <= own_uid <= 65535 and by_label["final-roster"]["uid"] == own_uid,
        "Own UID differs",
    )
    need(
        Counter(by_label["setup-view-S"]["names"]) == Counter(m.hex() for m in MARKERS)
        and Counter(by_label["setup-view-wrapper"]["names"])
        == Counter([b"S".hex(), b"H-\x9a".hex()])
        and by_label["setup-view-H"]["names"] == [],
        "Owned setup parent views differ",
    )
    high = by_label["setup-news-high"]["names"]
    need(
        high == [{"field": 323, "kind": 3, "name_hex": cases.CATEGORY.hex()}],
        "Owned News high differs",
    )
    baseline_news = {v["name_hex"] for v in pre_news}
    setup_news = (
        by_label["setup-news-root"]["names"] if "setup-news-root" in by_label else None
    )
    if setup_news is not None:
        need(
            {v["name_hex"] for v in setup_news} == baseline_news | {cases.NEWS.hex()},
            "Owned News root differs",
        )
    prior = {marker.hex(): "S" for marker in MARKERS}
    prior_views = {
        "S": by_label["setup-view-S"]["names"],
        "wrapper": by_label["setup-view-wrapper"]["names"],
        "H": by_label["setup-view-H"]["names"],
    }
    prior_types = {
        parent: by_label[f"setup-view-{parent}"]["types"] for parent in PARENTS
    }
    results = report["results"]
    need(len(results) == 12, "Twelve field outcomes required")
    for i, result in enumerate(results):
        need(
            result["index"] == i
            and result["field"] == plan["cells"][i]["field"]
            and result["value_hex"] == plan["cells"][i]["value_hex"],
            "Field cell identity differs",
        )
        if i < 6:
            marker = bytes.fromhex(plan["cells"][i]["marker_hex"])
            expected_before = (
                by_label["setup-view-S"]["names"]
                if i == 0
                else by_label[f"after-view-{i - 1}-S"]["names"]
            )
            need(
                result["before_parent"] == "S"
                and result["before_views"] == expected_before,
                "Before S view not cached",
            )
            views = {p: by_label[f"after-view-{i}-{p}"]["names"] for p in PARENTS}
            types = {p: by_label[f"after-view-{i}-{p}"]["types"] for p in PARENTS}
            found = location(views, marker)
            need(
                found is not None and result["selected_parent"] == found,
                "Missing/foreign selected marker",
            )
            assert found is not None
            exact_transition(prior_views, views, marker, found, prior_types, types)
            for other, old_parent in prior.items():
                if other != marker.hex():
                    need(
                        location(views, bytes.fromhex(other)) == old_parent,
                        "Other owned marker moved",
                    )
            need(
                result["after_views"] == views
                and result["after_info_parent_hex"] == PARENTS[str(found)].hex(),
                "Selected parent/readback differs",
            )
            prior[marker.hex()] = found
            prior_views = views
            prior_types = types
            reply = one(report["frames"], "main", result["request_id"])
            need(result["status"] == reply["error"], "Move status receipt differs")
            if found == "S":
                need(reply["error"] != 0, "Successful move without effect ambiguous")
            else:
                need(reply["error"] == 0, "Failed move changed selected parent")
        else:
            reply = one(report["frames"], "main", result["request_id"])
            need(result["status"] == reply["error"], "News status receipt differs")
            if reply["error"] == 0:
                actual = news_view(reply)
                need(
                    result["names"] == actual
                    and result["selected_parent"]
                    in {"news-root", "news-high", "empty"},
                    "News readback differs",
                )
                names = Counter(v["name_hex"] for v in actual)
                expected = Counter(v["name_hex"] for v in pre_news)
                expected[cases.NEWS.hex()] += 1
                if names == expected:
                    selected = "news-root"
                elif names == Counter([cases.CATEGORY.hex()]):
                    selected = "news-high"
                elif not names:
                    selected = "empty"
                else:
                    raise ValueError("Foreign News selected parent")
                need(
                    result["selected_parent"] == selected,
                    "News selected parent differs",
                )
            else:
                need(
                    result["selected_parent"] == "error" and result["names"] == [],
                    "News error selection differs",
                )
    need(
        Counter(by_label["final-files-root"]["names"]) == Counter(pre_files),
        "Files root not restored",
    )
    final_news = by_label["final-news-root"]["names"]
    need(
        Counter((v["field"], v["kind"], v["name_hex"]) for v in final_news)
        == Counter((v["field"], v["kind"], v["name_hex"]) for v in pre_news),
        "News root not restored",
    )
    need(
        report["mutation_count"] == 20 and report["request_count"] == 82,
        "Request/mutation ceiling differs",
    )


def verify_report(plan: dict, report: dict) -> None:
    """Check the finished report's status, hashes, event order and streams against the plan."""
    need(report["status"] == "completed", "Path matrix incomplete")
    need(
        report["plan_sha256"] == sha((json.dumps(plan, indent=2) + "\n").encode())
        and report["source_sha256"] == sha(Path(__file__).read_bytes())
        and report["cases_sha256"] == sha(Path(cases.__file__).read_bytes())
        and report["oracle_sha256"] == ORACLE_SHA256,
        "Plan/source/oracle differs",
    )
    events = report["events"]
    streams: dict[str, dict[str, str]] = {}
    prior_ns = -1
    for event in events:
        need(event["elapsed_ns"] >= prior_ns, "Nonmonotonic event")
        prior_ns = event["elapsed_ns"]
        s = streams.setdefault(
            event["connection"], {"sent_hex": "", "received_hex": ""}
        )
        if event["event"] == "send":
            s["sent_hex"] += event["hex"]
        elif event["event"] == "receive":
            s["received_hex"] += event["hex"]
    need(streams == report["streams"], "Raw stream/event mismatch")
    for frame in report["frames"]:
        raw = bytes.fromhex(frame["raw_hex"])
        need(
            all(frame.get(k) == v for k, v in decode_frame(raw).items()),
            "Frame/raw mismatch",
        )
    received_end = 0
    event_boundaries: list[tuple[int, int]] = []
    for event_index, event in enumerate(events):
        if event["event"] != "receive":
            continue
        received_end += len(bytes.fromhex(event["hex"]))
        event_boundaries.append((received_end, event_index))
    frame_end = len(bytes.fromhex(cases.HELLO_REPLY))
    for frame in report["frames"]:
        frame_end += len(bytes.fromhex(frame["raw_hex"]))
        containing = next(
            (index for end, index in event_boundaries if end >= frame_end), None
        )
        need(
            containing is not None
            and events[containing]["elapsed_ns"] <= frame["arrival_elapsed_ns"]
            and (
                containing + 1 == len(events)
                or frame["arrival_elapsed_ns"] <= events[containing + 1]["elapsed_ns"]
            ),
            "Frame arrival outside captured receive bracket",
        )
    for connection in ("main",):
        sent = cases.HELLO
        expected = report["actions"]
        prior_end = 0
        for action in expected:
            first, last = action["event_range"]
            need(
                prior_end <= first < last <= len(events)
                and action["connection"] == connection
                and events[last - 1]["elapsed_ns"] <= action["elapsed_ns"]
                and (
                    last == len(events)
                    or action["elapsed_ns"] <= events[last]["elapsed_ns"]
                )
                and "".join(
                    e["hex"] for e in events[first:last] if e["event"] == "send"
                )
                == action["hex"],
                "Action/send event or time bracket differs",
            )
            sent += action["hex"]
            prior_end = last
        need(streams[connection]["sent_hex"] == sent, "Sent request stream differs")
        received = streams[connection]["received_hex"]
        parsed = "".join(
            f["raw_hex"] for f in report["frames"] if f["connection"] == connection
        )
        need(
            received
            == cases.HELLO_REPLY + parsed + report["unparsed_hex"].get(connection, ""),
            "Received bytes omitted",
        )
        terminals = [
            e["event"]
            for e in events
            if e["connection"] == connection and e["event"] in {"eof", "rst"}
        ]
        need(len(terminals) <= 1, "Contradictory socket terminals")
        need(
            report["terminals"].get(connection)
            == (terminals[0] if terminals else "bounded_no_eof"),
            "Terminal label differs from events",
        )
    need(
        len(report["actions"]) == 82 and report["actions"][0]["label"] == "main-login",
        "Action ledger differs",
    )
    views = {v["label"]: v for v in report["views"]}
    need(len(views) == len(report["views"]), "Duplicate retained view")
    for action, spec in zip(report["actions"][1:], plan["requests"], strict=True):
        need(
            action["label"] == spec["label"] and action["connection"] == "main",
            "Request label/phase differs",
        )
        parent = (
            bytes.fromhex(action["dynamic_parent_hex"])
            if spec["fields"] is None
            else None
        )
        need(
            action["hex"] == cases.raw_request(spec, parent), "Request fields/ID differ"
        )
        reply = one(report["frames"], action["connection"], spec["id"])
        need(
            reply["flags"] == 0 and reply["type"] == 0 and reply["is_reply"] == 1,
            "Non-direct reply",
        )
        label = spec["label"]
        if spec["phase"] in {"initial", "setup-view", "final"} or label.startswith(
            "after-view-"
        ):
            expected_view = record_view([], label, reply)
            need(views.get(label) == expected_view, "View/raw reply differs")
        if label.startswith(("before-info-", "after-info-")):
            file_info(
                reply,
                bytes.fromhex(
                    spec["marker_hex"] if spec["marker_hex"] else spec["fields"][0][1]
                ),
            )
    login_gate(report["frames"], "main")
    classify_views(plan, report)
    need(
        report["terminals"].get("main") in {"eof", "rst", "bounded_no_eof"},
        "Missing finite terminal",
    )
    need(
        all(not value for value in report["unparsed_hex"].values()),
        "Completed case has partial frame",
    )


def exchange(
    wire: Wire, spec: dict, connection: str, parent: bytes | None = None
) -> dict:
    """Send one planned request, count it and wait for its reply."""
    if connection == "main":
        need(wire.request_count < 99, "Per-connection request cap reached")
    raw = cases.raw_request(spec, parent)
    before = len(wire.frames)
    wire.send(connection, raw, spec["label"])
    if connection == "main":
        wire.request_count += 1
        wire.partial["request_count"] = wire.request_count
        if spec["mutation"]:
            wire.partial["mutation_count"] += 1
    if parent is not None:
        wire.actions[-1]["dynamic_parent_hex"] = parent.hex()
    wire.wait_for(
        lambda: bool(wire.match(connection, 0, spec["id"], 1)), 5, spec["label"]
    )
    reply = one(wire.frames[before:], connection, spec["id"])
    need(reply["flags"] == 0, "Reply flags differ")
    return reply


def connect_login(wire: Wire, name: str, guard) -> None:
    """Connect the only open connection, handshake, log in and wait for the grant and agreement."""
    guard()
    need(len(wire.recorder.sockets) == 0, "Previous connection still open")
    wire.execute({"op": "connect", "connection": name, "endpoint": "control"})
    wire.execute({"op": "send", "connection": name, "hex": cases.HELLO})
    wire.execute(
        {"op": "read", "connection": name, "size": 8, "expect_hex": cases.HELLO_REPLY}
    )
    wire.buffers[name] = bytearray()
    wire.send(name, login()[3]["hex"], f"{name}-login")
    if name == "main":
        wire.request_count += 1
    wire.wait_for(
        lambda: (
            bool(wire.match(name, 0, 1, 1))
            and bool(wire.match(name, 354, None, 0))
            and bool(wire.match(name, 109, None, 0))
        ),
        5,
        f"{name} login",
    )
    login_gate(wire.frames, name)


def record_view(views: list[dict], label: str, reply: dict) -> dict:
    """Record a view reply: its status, fields and the names it lists."""
    if reply["error"]:
        return {
            "label": label,
            "status": reply["error"],
            "fields": reply["fields"],
            "names": [],
        }
    if "news" in label:
        names = news_view(reply)
    elif "accounts" in label or "roster" in label:
        names = []
    else:
        names = file_view(reply)
    value = {"label": label, "status": 0, "fields": reply["fields"], "names": names}
    if label.endswith("files-root") or label.startswith(("setup-view-", "after-view-")):
        value["types"] = file_types(reply)
    if "accounts" in label:
        value["accounts"] = enumeration(reply)
    if "roster" in label:
        rows = roster(reply)
        need(len(rows) == 1, "Non-solo admin roster")
        value["uid"] = rows[0]["uid"]
        value["name_hex"] = rows[0]["name_hex"]
    views.append(value)
    return value


def perform(wire: Wire, plan: dict, guard) -> dict:
    """Run the path field matrix, recording views, results and progress."""
    views: list[dict] = []
    results: list[dict] = []
    progress: list[str] = []
    wire.partial = {
        "views": views,
        "results": results,
        "progress": progress,
        "own_uid": None,
        "current_case_index": None,
        "request_count": 0,
        "mutation_count": 0,
    }
    connect_login(wire, "main", guard)
    wire.partial["request_count"] = wire.request_count
    specs = plan["requests"]
    after_views: dict[str, list[str]] = {}
    first_views: dict[str, list[str]] = {}
    before_case_views: dict[str, list[str]] = {}
    first_types: dict[str, dict[str, str]] = {}
    before_case_types: dict[str, dict[str, str]] = {}
    after_types: dict[str, dict[str, str]] = {}
    selected: dict[str, str] = {m.hex(): "S" for m in MARKERS}
    initial_news: list[dict] = []
    for spec in specs:
        label, phase = spec["label"], spec["phase"]
        if phase.startswith(("files-", "news-")):
            wire.partial["current_case_index"] = int(phase.split("-")[1])
        if spec["fields"] is None:
            marker = bytes.fromhex(spec["marker_hex"])
            parent_name = selected.get(marker.hex())
            need(parent_name in PARENTS, "Dynamic selected parent absent")
            reply = exchange(wire, spec, "main", PARENTS[str(parent_name)])
        else:
            reply = exchange(wire, spec, "main")
        if phase in {"initial", "setup-view", "final"}:
            success(reply)
            value = record_view(views, label, reply)
            if label == "initial-roster":
                wire.partial["own_uid"] = value["uid"]
            if label == "initial-files-root":
                need(cases.FILES.hex() not in value["names"], "Owned Files name exists")
            if label == "initial-news-root":
                initial_news = value["names"]
                need(
                    cases.NEWS.hex() not in {v["name_hex"] for v in initial_news},
                    "Owned News name exists",
                )
            if label.startswith("setup-view-"):
                key = label.removeprefix("setup-view-")
                first_views[key] = value["names"]
                first_types[key] = value["types"]
                if key == "H":
                    need(
                        Counter(first_views.get("S", []))
                        == Counter(m.hex() for m in MARKERS)
                        and Counter(first_views.get("wrapper", []))
                        == Counter([b"S".hex(), b"H-\x9a".hex()])
                        and first_views.get("H") == [],
                        "Foreign or duplicate setup entry",
                    )
            if label == "setup-news-high":
                need(
                    value["names"]
                    == [{"field": 323, "kind": 3, "name_hex": cases.CATEGORY.hex()}],
                    "News high setup differs",
                )
        elif phase == "setup" or phase == "cleanup":
            success(reply)
        elif phase.startswith("files-"):
            i = int(phase[6:])
            marker = b"p" + bytes([48 + i])
            if label.startswith("before-info-"):
                file_info(reply, marker)
                before_case_views = dict(first_views if i == 0 else after_views)
                before_case_types = dict(first_types if i == 0 else after_types)
                after_views = {}
                after_types = {}
                before = before_case_views["S"]
                need(marker.hex() in before, "Marker missing before 208")
                results.append(
                    {
                        "index": i,
                        "field": 212,
                        "value_hex": plan["cells"][i]["value_hex"],
                        "before_parent": "S",
                        "before_views": before,
                        "same_parent_noop": False,
                    }
                )
            elif label.startswith("move-"):
                results[-1].update(
                    request_id=spec["id"],
                    status=reply["error"],
                    error_fields=reply["fields"],
                )
            elif label.startswith("after-view-"):
                success(reply)
                parent_name = label.rsplit("-", 1)[-1]
                after_views[parent_name] = file_view(reply)
                after_types[parent_name] = record_view(views, label, reply)["types"]
                if parent_name == "H":
                    found = location(after_views, marker)
                    if found is None:
                        # One explicitly counted read-only Files-root stop probe.
                        need(wire.request_count < 99, "No stop-probe request reserve")
                        extra = cases.request(
                            f"stop-files-root-{i}",
                            200,
                            9000 + i,
                            [(202, cases.FILES_ROOT)],
                            "stop-probe",
                        )
                        extra_reply = exchange(wire, extra, "main")
                        record_view(views, extra["label"], extra_reply)
                        raise ValueError("Marker outside selected owned parents")
                    exact_transition(
                        before_case_views,
                        after_views,
                        marker,
                        found,
                        before_case_types,
                        after_types,
                    )
                    for other, old in selected.items():
                        if other != marker.hex():
                            need(
                                location(after_views, bytes.fromhex(other)) == old,
                                "Other marker location changed",
                            )
                    need(
                        (found != "S" and results[-1]["status"] == 0)
                        or (found == "S" and results[-1]["status"] != 0),
                        "Move status/location ambiguous",
                    )
                    results[-1]["selected_parent"] = found
                    results[-1]["after_views"] = dict(after_views)
                    selected[marker.hex()] = found
            elif label.startswith("after-info-"):
                found = selected[marker.hex()]
                file_info(reply, marker)
                results[-1]["after_info_parent_hex"] = PARENTS[found].hex()
            elif label.startswith("barrier-"):
                success(reply)
        elif phase.startswith("news-"):
            if label.startswith("news-"):
                i = int(phase[5:])
                actual = news_view(reply) if reply["error"] == 0 else []
                names = Counter(v["name_hex"] for v in actual)
                root = Counter(v["name_hex"] for v in initial_news)
                root[cases.NEWS.hex()] += 1
                selected_parent = (
                    (
                        "news-root"
                        if names == root
                        else "news-high"
                        if names == Counter([cases.CATEGORY.hex()])
                        else "empty"
                        if not names
                        else "foreign"
                    )
                    if reply["error"] == 0
                    else "error"
                )
                need(selected_parent != "foreign", "Foreign News selection")
                results.append(
                    {
                        "index": i,
                        "field": 325,
                        "value_hex": plan["cells"][i]["value_hex"],
                        "request_id": spec["id"],
                        "status": reply["error"],
                        "error_fields": reply["fields"] if reply["error"] else [],
                        "names": actual,
                        "selected_parent": selected_parent,
                    }
                )
            else:
                success(reply)
        progress.append(label)
        if label.startswith(("barrier-files-", "barrier-news-")):
            wire.partial["current_case_index"] = None
    need(len(results) == 12, "Incomplete matrix")
    return {"views": views, "results": results, "progress": progress}


def run(plan_dir: Path, receipt_path: Path, binary: Path, output: Path) -> dict:
    """Check the plan, receipt and namespace, run the matrix and write the report."""
    plan = prepared(plan_dir)
    receipt_raw = receipt_path.read_bytes()
    receipt = json.loads(receipt_raw)
    deadline = utc(receipt["deadline_utc"])
    remaining = (deadline - datetime.now(timezone.utc)).total_seconds()
    need(remaining >= 390, "Fixed epoch start margin under 390 seconds")
    need(
        receipt["emulator_pid"] == plan["environment"]["emulator_pid"],
        "Runtime receipt differs",
    )
    runtime_gate(receipt, plan["environment"], deadline)
    need(
        os.stat("/proc/self/ns/net").st_ino
        == plan["environment"]["emulator_netns_inode"],
        "Wrong network namespace",
    )
    need(sha(binary.read_bytes()) == ORACLE_SHA256, "Oracle binary differs")
    output.mkdir(parents=True, exist_ok=False)
    wire_plan = {
        "endpoint": plan["endpoint"],
        "schedule": {
            "max_bytes": plan["limits"]["max_bytes"],
            "max_frames": plan["limits"]["max_frames"],
            "max_tail_bytes_per_flow": plan["limits"]["max_tail_bytes"],
            "max_simultaneous": 1,
        },
    }
    wire = Wire(
        wire_plan,
        min(time.monotonic() + 210, time.monotonic() + remaining),
        lambda: runtime_gate(receipt, plan["environment"], deadline),
    )
    wire.request_count = 0
    status, error = "completed", ""
    try:
        perform(
            wire, plan, lambda: runtime_gate(receipt, plan["environment"], deadline)
        )
        runtime_gate(receipt, plan["environment"], deadline)
    except (OSError, ValueError, TimeoutError, EOFError, KeyError, IndexError) as exc:
        status, error = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        try:
            wire.close_all()
        except (OSError, ValueError, TimeoutError) as exc:
            status, error = "failed", error + f"; close {type(exc).__name__}: {exc}"
            for name, sock in list(wire.recorder.sockets.items()):
                sock.close()
                wire.recorder.sockets.pop(name)
                wire.recorder.event(-1, name, "close_after_failure")
    report = {
        "schema_version": 1,
        "status": status,
        "error": error,
        "plan_sha256": sha((plan_dir / "plan.json").read_bytes()),
        "source_sha256": sha(Path(__file__).read_bytes()),
        "cases_sha256": sha(Path(cases.__file__).read_bytes()),
        "oracle_sha256": ORACLE_SHA256,
        "receipt_sha256": sha(receipt_raw),
        "started_at_utc": wire.recorder.started_at_utc,
        "recorded_at_utc": datetime.now(timezone.utc).isoformat(),
        "events": wire.recorder.events,
        "frames": wire.frames,
        "actions": wire.actions,
        "streams": wire.recorder.streams(),
        "terminals": wire.terminals,
        "unparsed_hex": {name: raw.hex() for name, raw in wire.buffers.items()},
        "views": getattr(wire, "partial", {}).get("views", []),
        "results": getattr(wire, "partial", {}).get("results", []),
        "progress": getattr(wire, "partial", {}).get("progress", []),
        "request_count": wire.request_count,
        "mutation_count": getattr(wire, "partial", {}).get("mutation_count", 0),
        "own_uid": getattr(wire, "partial", {}).get("own_uid"),
        "current_case_index": getattr(wire, "partial", {}).get("current_case_index"),
        "stopped_catalogue_proof": "not_exercised_by_live_runner",
    }
    if status == "completed":
        try:
            verify_report(plan, report)
        except (ValueError, KeyError, IndexError) as exc:
            report["status"] = "failed"
            report["error"] = f"Offline report check: {exc}"
    (output / "plan.json").write_bytes((plan_dir / "plan.json").read_bytes())
    (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report


def main() -> None:
    """Parse the command line, run the capture and exit non-zero unless it completed."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--plan-dir", type=Path, required=True)
    parser.add_argument("--capture-receipt", type=Path, required=True)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    result = run(args.plan_dir, args.capture_receipt, args.binary, args.output)
    print(json.dumps({"status": result["status"], "error": result["error"]}))
    if result["status"] != "completed":
        raise SystemExit(1)


if __name__ == "__main__":
    main()
