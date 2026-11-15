#!/usr/bin/env python3
"""Capture bounded PostgreSQL startup evidence before test slot cleanup."""
import json
import os
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
stop = Path(sys.argv[3])
ready = Path(sys.argv[4])
out.parent.mkdir(parents=True, exist_ok=True)
seen_lengths = {}
seen_pids = set()
started = time.monotonic()
limit = 8_000_000
with out.open("w") as record:
    def emit(item):
        if record.tell() > limit:
            return
        record.write(json.dumps(item, ensure_ascii=False) + "\n")
        record.flush()

    emit({"started_ns": time.time_ns(), "root": str(root), "pid": os.getpid()})
    ready.write_text(str(time.time_ns()))
    next_proc_scan = 0.0
    while not stop.exists() and time.monotonic() - started < 2500:
        for slot in (root / "data").glob("*"):
            if not slot.is_dir():
                continue
            for name in ("start.log", "postmaster.pid"):
                path = slot / name
                try:
                    data = path.read_bytes()
                except OSError:
                    continue
                key = str(path)
                prior = seen_lengths.get(key, 0)
                if len(data) < prior:
                    prior = 0
                if len(data) > prior:
                    chunk = data[prior:][:16384]
                    emit({"time_ns": time.time_ns(), "path": key,
                          "offset": prior, "content": chunk.decode("utf-8", "replace"),
                          "file_size": len(data)})
                    seen_lengths[key] = len(data)
        now = time.monotonic()
        if now >= next_proc_scan:
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit() or proc.name in seen_pids:
                    continue
                try:
                    raw = (proc / "cmdline").read_bytes()
                except OSError:
                    continue
                args = [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]
                if not args or Path(args[0]).name not in ("pg_ctl", "postgres", "initdb"):
                    continue
                if str(root) not in " ".join(args):
                    continue
                seen_pids.add(proc.name)
                try:
                    namespace = os.readlink(proc / "ns/net")
                except OSError:
                    namespace = None
                emit({"time_ns": time.time_ns(), "pid": int(proc.name),
                      "net_namespace": namespace, "argv": args})
            next_proc_scan = now + 0.1
        time.sleep(0.025)
    emit({"stopped_ns": time.time_ns(), "stop_requested": stop.exists(),
          "observed_files": len(seen_lengths), "observed_pids": len(seen_pids),
          "output_bytes": record.tell()})
