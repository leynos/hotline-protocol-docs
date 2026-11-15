#!/usr/bin/env python3
"""Observe two overlapping exact PostgreSQL test executions under one root."""
import json
import os
import subprocess
import sys
import tempfile
import time
from pathlib import Path

base = Path("/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd")
diag = base / "mothra/state/delegation/c8-postgres"
root = diag / "root-pair"
capture = diag / "pair-capture.jsonl"
mxd = base / "mxd"
if len(sys.argv) == 2 and sys.argv[1] == "--watch":
    seen = {}
    with capture.open("w") as out:
        out.write(json.dumps({"ready_ns": time.time_ns()}) + "\n")
        out.flush()
        deadline = time.monotonic() + 450
        while not (diag / "pair-stop").exists() and time.monotonic() < deadline:
            for slot in (root / "data").glob("*"):
                if not slot.is_dir():
                    continue
                for name in ("start.log", "postmaster.pid"):
                    source = slot / name
                    try:
                        data = source.read_bytes()
                    except OSError:
                        continue
                    key = str(source)
                    stamp = (len(data), hash(data))
                    if seen.get(key) == stamp:
                        continue
                    seen[key] = stamp
                    out.write(json.dumps({
                        "time_ns": time.time_ns(), "path": key,
                        "content": data[:65536].decode("utf-8", "replace"),
                        "total_bytes": len(data),
                    }) + "\n")
                    out.flush()
            for proc in Path("/proc").iterdir():
                if not proc.name.isdigit():
                    continue
                try:
                    raw = (proc / "cmdline").read_bytes()
                except OSError:
                    continue
                args = [x.decode("utf-8", "replace") for x in raw.split(b"\0") if x]
                if not args or Path(args[0]).name not in ("pg_ctl", "postgres", "initdb"):
                    continue
                if str(root) not in " ".join(args) or proc.name in seen:
                    continue
                seen[proc.name] = (0, 0)
                out.write(json.dumps({"time_ns": time.time_ns(),
                                      "pid": int(proc.name), "argv": args}) + "\n")
                out.flush()
            time.sleep(0.02)
        out.write(json.dumps({"stopped_ns": time.time_ns()}) + "\n")
    raise SystemExit(0)

root.mkdir(parents=True, exist_ok=True)
watch = subprocess.Popen(["python3", str(Path(__file__).resolve()), "--watch"])
for _ in range(200):
    if capture.is_file() and '"ready_ns"' in capture.read_text():
        break
    if watch.poll() is not None:
        raise SystemExit(f"watcher exited early: {watch.returncode}")
    time.sleep(0.01)
else:
    watch.terminate()
    raise SystemExit("watcher readiness timeout")
env = os.environ.copy()
env.update({
    "PATH": "/home/leynos/.cargo/bin:/home/leynos/.local/bin:/usr/local/bin:/usr/bin:/bin",
    "CARGO_TARGET_DIR": str(base / "mothra/state/delegation/mxd-target"),
    "CARGO_NET_OFFLINE": "true", "CARGO_BUILD_JOBS": "1",
    "PG_EMBED_ROOT": str(root),
    "PG_RUNTIME_DIR": "/var/tmp/pg-embed-1000/install",
    "PG_PASSWORD": "mxd-embedded-test",
    "NEXTEST_PROFILE": "postgres",
    "RUSTFLAGS": "-D warnings -Zthreads=8 -Clink-arg=-fuse-ld=mold",
})
env.pop("CARGO_ENCODED_RUSTFLAGS", None)
cmd = [
    "cargo", "nextest", "run", "--locked", "--no-default-features",
    "--features", "postgres test-support legacy-networking",
    "--test", "wireframe_compat_guardrails_bdd", "--test-threads", "1",
    "-E", "test(wireframe_compat_guardrails_login_failure_does_not_include_banner_fields)",
]
outputs = [tempfile.TemporaryFile() for _ in range(2)]
starts = []
processes = []
for output in outputs:
    starts.append(time.time_ns())
    processes.append(subprocess.Popen(cmd, cwd=mxd, env=env, stdout=output,
                                      stderr=subprocess.STDOUT))
try:
    codes = [process.wait(timeout=420) for process in processes]
except subprocess.TimeoutExpired:
    for process in processes:
        if process.poll() is None:
            process.terminate()
    codes = [process.wait(timeout=10) for process in processes]
finally:
    (diag / "pair-stop").write_text(str(time.time_ns()))
    watch.wait(timeout=10)
for output in outputs:
    output.seek(0)
logs = [output.read().decode("utf-8", "replace") for output in outputs]
(diag / "pair-result.json").write_text(json.dumps({
    "argv": cmd, "env_overrides": {k: env[k] for k in (
        "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "CARGO_BUILD_JOBS",
        "PG_EMBED_ROOT", "PG_RUNTIME_DIR", "NEXTEST_PROFILE", "RUSTFLAGS")},
    "test_start_ns": starts, "test_exit_codes": codes,
    "watcher_exit_code": watch.returncode, "test_logs": logs,
}, indent=2) + "\n")
print("test exits", codes, "watcher exit", watch.returncode)
