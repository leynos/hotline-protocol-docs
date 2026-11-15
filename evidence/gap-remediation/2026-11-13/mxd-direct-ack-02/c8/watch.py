#!/usr/bin/env python3
"""Capture owned embedded PostgreSQL startup files before slot cleanup."""
import json
import os
import shutil
import sys
import time
from pathlib import Path

root = Path(sys.argv[1])
out = Path(sys.argv[2])
stop = Path(sys.argv[3])
out.mkdir(parents=True, exist_ok=True)
seen = {}
started = time.monotonic()
with (out / "watch.jsonl").open("w") as record:
    (out / "watch-ready").write_text(str(time.time_ns()))
    while not stop.exists() and time.monotonic() - started < 450:
        for path in (root / "data").glob("*"):
            if not path.is_dir():
                continue
            for name in ("start.log", "postmaster.pid"):
                source = path / name
                if source.is_file():
                    try:
                        data = source.read_bytes()
                    except OSError:
                        continue
                    key = str(source)
                    stamp = (len(data), hash(data))
                    if seen.get(key) != stamp:
                        seen[key] = stamp
                        target = out / f"{path.name}-{name}"
                        target.write_bytes(data[:262144])
                        record.write(json.dumps({
                            "time_ns": time.time_ns(), "path": key,
                            "captured_bytes": min(len(data), 262144),
                            "file_size": len(data),
                        }) + "\n")
                        record.flush()
        if len(seen) < 30:
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    raw = (proc / "cmdline").read_bytes()
                except OSError:
                    continue
                if not raw:
                    continue
                args = [part.decode("utf-8", "replace") for part in raw.split(b"\0") if part]
                exe = Path(args[0]).name if args else ""
                if exe not in ("pg_ctl", "postgres", "initdb"):
                    continue
                if str(root) not in " ".join(args):
                    continue
                key = f"pid:{proc.name}"
                if key in seen:
                    continue
                seen[key] = (0, 0)
                record.write(json.dumps({"time_ns": time.time_ns(),
                                         "pid": int(proc.name), "argv": args}) + "\n")
                record.flush()
        time.sleep(0.02)
    record.write(json.dumps({"watcher_stopped_ns": time.time_ns(),
                             "stop_file": stop.exists()}) + "\n")
