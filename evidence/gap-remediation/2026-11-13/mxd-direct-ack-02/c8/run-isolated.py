#!/usr/bin/env python3
"""Run one exact PostgreSQL BDD case with a separate bounded file observer."""
import json
import os
import subprocess
import time
from pathlib import Path

base = Path("/data/leynos/Projects/mothra/state/delegation/workspaces/batch-02-mxd")
mxd = base / "mxd"
diag = base / "mothra/state/delegation/c8-postgres"
root = diag / "root"
out = diag / "isolated"
stop = out / "stop"
watch = subprocess.Popen(
    ["python3", str(diag / "watch.py"), str(root), str(out), str(stop)],
    cwd=mxd, stdout=(out / "watch.stdout").open("w"),
    stderr=(out / "watch.stderr").open("w"),
)
for _ in range(200):
    if (out / "watch-ready").exists():
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
    "CARGO_NET_OFFLINE": "true",
    "CARGO_BUILD_JOBS": "1",
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
(out / "command.json").write_text(json.dumps({
    "cwd": str(mxd), "argv": cmd,
    "env_overrides": {k: env[k] for k in (
        "CARGO_TARGET_DIR", "CARGO_NET_OFFLINE", "CARGO_BUILD_JOBS",
        "PG_EMBED_ROOT", "PG_RUNTIME_DIR", "NEXTEST_PROFILE", "RUSTFLAGS")},
    "pg_password": "test fixture value from Makefile",
}, indent=2) + "\n")
started = time.time_ns()
try:
    with (out / "nextest.log").open("w") as log:
        result = subprocess.run(cmd, cwd=mxd, env=env, stdout=log,
                                stderr=subprocess.STDOUT, timeout=420, check=False)
    code = result.returncode
except subprocess.TimeoutExpired:
    code = 124
finally:
    stop.write_text(str(time.time_ns()))
    try:
        watch.wait(timeout=10)
    except subprocess.TimeoutExpired:
        watch.terminate()
        watch.wait(timeout=5)
(out / "result.json").write_text(json.dumps({
    "exit_code": code, "started_ns": started, "ended_ns": time.time_ns(),
    "watcher_exit_code": watch.returncode,
}, indent=2) + "\n")
print("test exit", code, "watcher exit", watch.returncode)
