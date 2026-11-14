#!/usr/bin/env python3
"""Replay the C50 A7 and one focus event from a frozen, offline corpus."""

import argparse
import datetime as dt
import hashlib
import json
import struct
import zlib
from pathlib import Path

from pcap_tcp import lifetime, read_packets, stream
from protocol_capture import verify_capture

# fmt: off
PLAN_SHA = "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e"
DRIVER_SHA = "2fba0972f4d9a8e3845c4204dce150dd7c90da0e19a9e5720d5289e2c94faf01"
PREFIX_SHA = "b4c6dc15be0d82de42d3aa7102c1feca67397b978591ac8be2d2c846d6a62e7c"
OBSERVER_SHA = "4a39d24fbc68f492558deacb4794829d145e7cc100bab0acb8945f5497d4b3d4"
AS_PREPARED_SHA = "deec49121248489d2eed9a2a2c63cdbc2422d3026147bb3cbce74b6fbe76018a"
APP_SHA = "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b"
EXE_SHA = "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
ROM_SHA = "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd"
BASE_SHA = "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910"


def require(ok: bool, reason: str) -> None:
    if not ok:
        raise ValueError(reason)


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(path: Path) -> dict:
    return json.loads(path.read_text())


def inventory(corpus: Path) -> None:
    manifest = load(corpus / "manifest.json")
    require(manifest["schema"] == "native-ui-focus-01", "Corpus schema differs")
    files = manifest["files"]
    actual = {str(p.relative_to(corpus)) for p in corpus.rglob("*") if p.is_file() and p.name not in {"manifest.json", "SHA256SUMS"}}
    require(actual == set(files), "Corpus inventory differs")
    for name, digest in files.items():
        require(sha(corpus / name) == digest, f"Corpus SHA differs: {name}")
    lines = [f"{digest}  {name}" for name, digest in sorted(files.items())]
    require((corpus / "SHA256SUMS").read_text().splitlines() == lines, "SHA list differs")
    provenance = load(corpus / "source-provenance.json")
    require(provenance["schema"] == manifest["schema"], "Provenance schema differs")
    require(set(provenance["sources"]) == set(files) - {"source-provenance.json"}, "Source set differs")
    for name, record in provenance["sources"].items():
        path = corpus / name
        require(sha(path) == record["sha256"] and path.stat().st_size == record["bytes"], f"Source differs: {name}")


def png_rows(path: Path) -> list[bytes]:
    """Read the captured 1024x768 RGB PNG without executing image code."""
    data = path.read_bytes()
    require(data[:8] == b"\x89PNG\r\n\x1a\n", "Focus PNG signature differs")
    pos, chunks, header = 8, [], None
    while pos + 12 <= len(data):
        length = struct.unpack_from(">I", data, pos)[0]
        kind = data[pos + 4 : pos + 8]
        body = data[pos + 8 : pos + 8 + length]
        require(len(body) == length and pos + length + 12 <= len(data), "Focus PNG chunk truncated")
        crc = struct.unpack_from(">I", data, pos + 8 + length)[0]
        require(zlib.crc32(kind + body) == crc, "Focus PNG CRC differs")
        if kind == b"IHDR":
            header = struct.unpack(">IIBBBBB", body)
        elif kind == b"IDAT":
            chunks.append(body)
        elif kind == b"IEND":
            break
        pos += 12 + length
    require(header == (1024, 768, 8, 2, 0, 0, 0), "Focus PNG format differs")
    raw = zlib.decompress(b"".join(chunks))
    stride = 1024 * 3
    require(len(raw) == 768 * (stride + 1), "Focus PNG pixel length differs")
    rows, previous, pos = [], bytes(stride), 0
    for _ in range(768):
        mode = raw[pos]
        row = bytearray(raw[pos + 1 : pos + 1 + stride])
        require(mode in range(5), "Focus PNG filter differs")
        for index in range(stride):
            left = row[index - 3] if index >= 3 else 0
            up = previous[index]
            upper_left = previous[index - 3] if index >= 3 else 0
            if mode == 1:
                value = left
            elif mode == 2:
                value = up
            elif mode == 3:
                value = (left + up) // 2
            elif mode == 4:
                predictor = left + up - upper_left
                value = min((left, up, upper_left), key=lambda v: abs(predictor - v))
            else:
                value = 0
            row[index] = (row[index] + value) & 255
        previous = bytes(row)
        rows.append(previous)
        pos += stride + 1
    return rows


def gold_count(rows: list[bytes], box: tuple[int, int, int, int]) -> int:
    x0, y0, x1, y1 = box
    return sum(rows[y][x * 3] > 200 and rows[y][x * 3 + 1] > 130
               and rows[y][x * 3 + 2] < 80 for y in range(y0, y1) for x in range(x0, x1))


def verify(corpus: Path) -> dict:
    corpus = corpus.resolve()
    inventory(corpus)
    boot, exp, prep = (corpus / name for name in ("boot", "experiment", "preparation"))
    require(sha(exp / "a7-original-plan.json") == PLAN_SHA, "Original A7 plan differs")
    require(sha(Path(__file__).with_name("protocol_capture.py")) == DRIVER_SHA, "A7 driver revision differs")
    original, asrun = load(exp / "a7-original-plan.json"), load(exp / "a7-as-run-plan.json")
    require(len(original["steps"]) == 29 and original["steps"] == asrun["steps"], "A7 steps differ")
    for key in original.keys() - {"environment", "endpoints"}:
        require(original[key] == asrun[key], f"A7 {key} differs")
    require(asrun["endpoints"] == {"control": {"host": "127.0.0.1", "port": 15750}, "data": {"host": "127.0.0.1", "port": 15751}}, "A7 endpoints differ")
    require(asrun["environment"]["emulator_pid"] == 2055952 and asrun["environment"]["captured_options"] is False, "A7 runtime or options caveat differs")
    report = verify_capture(exp / "capture")
    require((report["status"], report["completed_actions"], report["error"]) == ("failed", 21, "TimeoutError: timed out"), "A7 failed outcome differs")
    require(report["driver_sha256"] == DRIVER_SHA and report["oracle_sha256"] == APP_SHA, "A7 source identity differs")
    received = bytes.fromhex(report["streams"]["download"]["received_hex"])
    sent = bytes.fromhex(report["streams"]["download"]["sent_hex"])
    require(len(received) == 98304 and hashlib.sha256(received).hexdigest() == PREFIX_SHA, "A7 download prefix differs")
    event = next(e for e in report["events"] if e["connection"] == "download" and e["event"] == "connect")
    require(event["peer_address"] == ["127.0.0.1", 15751], "A7 data peer differs")
    local = event["local_address"][1]
    when = int(dt.datetime.fromisoformat(report["started_at_utc"]).timestamp() * 1_000_000) + event["elapsed_ns"] // 1000
    views = {}
    for name, client, server, port, filename in (("guest", "10.0.2.2", "10.0.2.15", 5501, "lab-guest.pcap"), ("namespace", "127.0.0.1", "127.0.0.1", 15751, "lab-namespace.pcap")):
        packets = read_packets(boot / filename)
        if name == "namespace":
            require(not any(p["src_port"] in (15500, 15501) or p["dst_port"] in (15500, 15501) for p in packets), "Primary bridge used")
        flow = lifetime(packets, (client, local), (server, port), when)
        require(sum(bool(p["flags"] & 2 and not p["flags"] & 16) for p in flow) == 1, f"{name} SYN association differs")
        body = stream(flow, (server, port), (client, local))
        require(body == received and stream(flow, (client, local), (server, port)) == sent, f"{name} packet stream differs")
        views[name] = {"bytes": len(body), "sha256": hashlib.sha256(body).hexdigest(), "pcap_sha256": sha(boot / filename)}
    require(read_packets(boot / "primary-host.pcap") == [], "Primary host traffic differs")
    for logfile in ("host-recorder.log", "ns-recorder.log"):
        require("0 packets dropped by kernel" in (boot / logfile).read_text(), "Recorder drop proof differs")
    before, after = (exp / "focus-event" / name for name in ("before.png", "after.png"))
    before_rows, after_rows = png_rows(before), png_rows(after)
    result = load(exp / "focus-event/result.json")
    require(result["event_count"] == 1 and result["status"] == "no_progress_after_verified_focus", "Focus event outcome differs")
    require(result["title_gold_before"] == gold_count(before_rows, (220, 35, 300, 46)) == 0, "Inactive Log title differs")
    require(result["title_gold_after"] == gold_count(after_rows, (220, 35, 300, 46)) == 278, "Activated Log title differs")
    require(before_rows[180][450 * 3 : 450 * 3 + 3] == b"\xff\xff\xff", "Blank Log click target differs")
    for stage in ("before", "after"):
        for name in ("guest", "namespace"):
            item = result[stage][name]
            require(item["bytes"] == views[name]["bytes"] and item["sha256"] == views[name]["sha256"] and item["local_port"] == local, f"{stage} {name} event stream differs")
            require(item["last_packet_us"] == result["before"][name]["last_packet_us"], f"{name} post-event packet tail differs")
    start = dt.datetime.fromisoformat(result["started_utc"])
    click = dt.datetime.fromisoformat(result["event_utc"])
    returned = dt.datetime.fromisoformat(result["event_return_utc"])
    ended = dt.datetime.fromisoformat(result["ended_utc"])
    require((click - start).total_seconds() >= 5 and (ended - returned).total_seconds() >= 10, "Plateau or observation duration differs")
    for name in ("guest", "namespace"):
        last = dt.datetime.fromtimestamp(result["before"][name]["last_packet_us"] / 1_000_000, dt.timezone.utc)
        require((click - last).total_seconds() >= 5, f"{name} packet plateau too short")
    revision = load(prep / "event-probe-revision.json")
    require(sha(prep / "observer-corrected.py.txt") == revision["corrected_sha256"] == OBSERVER_SHA, "Corrected observer differs")
    require(sha(prep / "observer-as-prepared.py.txt") == revision["original_sha256"] == AS_PREPARED_SHA, "As-prepared observer differs")
    corrected = (prep / "observer-corrected.py.txt").read_text()
    old = (prep / "observer-as-prepared.py.txt").read_text()
    require(old.replace("XTestFakeMotionEvent(display, -1, 450, 180, 0, 0)", "XTestFakeMotionEvent(display, -1, 450, 180, 0)") == corrected, "Observer correction scope differs")
    launch = load(exp / "observer-launch.json")
    argv = launch["argv"]
    require(argv[16:18] == ["--a7-pid", str(load(exp / "a7-main.json")["main_pid"])], "Observer runner binding differs")
    require(argv[11].endswith("/event_probe.py") and launch["exit"] == 0, "Corrected observer launch differs")
    outcome, terminal = load(exp / "outcome.json"), load(exp / "terminal.json")
    require(outcome["download_bytes"] == 98304 and outcome["observer_status"] == result["status"] and outcome["event_count"] == 1, "Outcome summary differs")
    require(terminal["actual_pid_gone"] and terminal["source_base_stat_unchanged"] and terminal["option_two_executed"] is False, "Lab retirement or option-two scope differs")
    require(terminal["a7_status"] == "failed" and terminal["a7_completed_actions"] == 21, "Terminal A7 status differs")
    require(all(terminal["views"][name]["pcap_sha256"] == views[name]["pcap_sha256"]
                and terminal["views"][name]["bytes"] == 98304 for name in views),
            "Terminal packet proof differs")
    require(terminal["primary_host_pcap_bytes"] == 24 and terminal["primary_bridge_used"] is False, "Primary port proof differs")
    signals, stops = load(exp / "cleanup-signals.json"), load(exp / "unit-stops.json")
    require(signals["pid_gone"] and len(signals["events"]) == 1 and signals["events"][0]["signal"] == "TERM" and signals["events"][0]["exit"] == 0, "Owned PID cleanup differs")
    require("stop exit5" in terminal["cleanup_note"] and any(x["unit"].startswith("mothra-sheep-") and x["exit"] == 5 for x in stops["results"]), "Cleanup anomaly lost")
    require(all("MainPID=0" in state for state in terminal["units"].values()), "Owned unit remains active")
    ready, identity = load(boot / "readiness.json"), load(boot / "identity.json")
    require(ready["observer_sha256"] == OBSERVER_SHA and ready["no_frontend_contact"], "Boot observer identity differs")
    require(ready["gui"]["sha256"] == sha(boot / "server-ready-initial.png") and ready["gui"]["log_title_gold_pixels"] == 0, "Boot GUI state differs")
    require(identity["pid"] == ready["actual_emulator"]["pid"] == 2055952 and identity["starttime"] == "4261101" and identity["exe_sha256"] == EXE_SHA, "Emulator identity differs")
    require(identity["netns"] == "net:[4026532615]" and identity["routes"] == "" and "127.0.0.1/8" in identity["addr"], "Lab route isolation differs")
    require(identity["fd6"].endswith("native-eventlab-one-01/working.dsk") and identity["fd16"].endswith("native-eventlab-c49/lab-guest.pcap"), "Owned emulator FDs differ")
    require(ready["original"]["primary"]["netns"] != identity["netns"] and ready["original"]["client"]["netns"] != identity["netns"], "Lab peer isolation differs")
    require(terminal["peers"] == ready["original"] and terminal["actual_pid"] == identity["pid"], "Primary or client identity changed")
    require(all("0 packets dropped by kernel" in "\n".join(lines) for lines in terminal["recorder_logs"].values()), "Terminal recorder drops unknown")
    preflight = load(exp / "preflight.json")
    require(preflight["observer_sha256"] == OBSERVER_SHA and preflight["emulator_pid"] == identity["pid"] and preflight["starttime"] == identity["starttime"], "Experiment identity differs")
    require(load(corpus / "runtime/build-manifest.json")["binary_sha256"] == EXE_SHA, "Emulator build differs")
    assets = load(corpus / "runtime/assets.json")
    require(assets["base_disk_sha256"] == BASE_SHA and assets["rom_sha256"] == ROM_SHA, "Base or ROM differs")
    prepared = load(prep / "postflight.json")
    require(prepared["source_unchanged"] and prepared["target"]["base.dsk"]["sha256"] == BASE_SHA and prepared["target"]["working.dsk"]["sha256"] == BASE_SHA and prepared["target"]["rom"]["sha256"] == ROM_SHA, "Prepared source differs")
    require(prepared["target"]["base.dsk"]["inode"] != prepared["source_after"]["base.dsk"]["inode"], "Owned disk copy differs")
    require("ramsize 536870912" in (corpus / "runtime/prefs.txt").read_text(), "RAM configuration differs")
    return {"status": "verified_failed_a7_and_negative_focus_event", "a7_actions": 21,
            "event_count": 1, "guest_bytes": views["guest"]["bytes"],
            "namespace_bytes": views["namespace"]["bytes"], "option_two_executed": False}


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("corpus", type=Path)
    print(json.dumps(verify(parser.parse_args().corpus), indent=2))


if __name__ == "__main__":
    main()
# fmt: on
