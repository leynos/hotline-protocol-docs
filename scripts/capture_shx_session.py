#!/usr/bin/env python3
"""Capture a compiled shx terminal session inside a repository-backed namespace."""

import argparse
import hashlib
import json
import os
import pty
import re
import select
import shutil
import signal
import time
from datetime import datetime, timezone
from pathlib import Path

from mothra_root import mothra_root
from protocol_capture import ORACLE_SHA256


def digest(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def capture(
    plan_path: Path, binary: Path, profile_path: Path, oracle: Path, output: Path
) -> dict:
    root = mothra_root().resolve()
    binary, output = binary.resolve(), output.resolve()
    require_paths = [binary, output]
    if any(not path.is_relative_to(root) for path in require_paths):
        raise ValueError("Peer binary and capture output must be inside mothra")
    plan = json.loads(plan_path.read_text())
    profile = json.loads(profile_path.read_text())
    if digest(oracle) != ORACLE_SHA256 or digest(binary) != profile["binary_sha256"]:
        raise ValueError("Peer or oracle identity mismatch")
    if profile["source_commit"] != "adb1bf8c8cb12f7eb2fa2c01673295a6312f262b":
        raise ValueError("Unknown historical source profile")
    for step in plan["steps"]:
        if any(c in step["command"] for c in "\0\r\n") or len(step["command"]) > 4096:
            raise ValueError("Require bounded single-line peer commands")
    if not plan["steps"] or plan["steps"][-1].get("expect_exit") != 0:
        raise ValueError("Require an explicit successful peer exit as the final step")
    bwrap, strace = shutil.which("bwrap"), shutil.which("strace")
    if not bwrap or not strace:
        raise ValueError("Require bwrap and strace")
    output.mkdir(parents=True, exist_ok=False)
    for name in ["home", "tmp", "work"]:
        (output / name).mkdir()
    (output / "plan.json").write_bytes(plan_path.read_bytes())
    (output / "peer-profile.json").write_bytes(profile_path.read_bytes())
    home_target = str(Path.home())
    guarded_home_file = Path.home() / ".hxvars"

    def home_file_state() -> dict:
        if not guarded_home_file.exists():
            return {"exists": False}
        stat = guarded_home_file.stat()
        return {
            "exists": True,
            "size": stat.st_size,
            "mtime_ns": stat.st_mtime_ns,
            "sha256": digest(guarded_home_file),
        }

    original_home_state = home_file_state()
    command = [
        bwrap,
        "--unshare-user",
        "--die-with-parent",
        "--ro-bind",
        "/",
        "/",
        "--bind",
        str(root),
        str(root),
        "--bind",
        str(output / "home"),
        home_target,
        "--bind",
        str(output / "tmp"),
        "/tmp",
        "--proc",
        "/proc",
        "--dev",
        "/dev",
        "--chdir",
        str(output / "work"),
        "--",
        strace,
        "-f",
        "-ttt",
        "-xx",
        "-yy",
        "-s",
        "131072",
        "-e",
        "trace=network,read,write,close,execve,exit_group",
        "-o",
        str(output / "syscalls.log"),
        str(binary),
        "-q",
        "-d",
    ]
    events: list[dict[str, str | int]] = []
    report = {
        "schema_version": 1,
        "profile": "compiled-historical-peer",
        "native_conformance": False,
        "identity_scope": "Local hashes checked; remote native process identity remains operator-reported",
        "oracle_sha256": ORACLE_SHA256,
        "peer_binary_sha256": digest(binary),
        "plan_sha256": digest(plan_path),
        "peer_profile_sha256": digest(profile_path),
        "driver_sha256": digest(Path(__file__)),
        "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "environment": plan["environment"],
        "terminal_environment": {
            **{key: os.environ.get(key) for key in ["LANG", "LC_ALL", "LC_CTYPE"]},
            "TERM": "dumb",
        },
        "command": command,
        "events": events,
        "completed_steps": 0,
        "status": "running",
        "error": "",
        "host_home_file_before": original_home_state,
    }
    began = time.monotonic_ns()
    pid, fd = pty.fork()
    if pid == 0:
        try:
            environment = dict(os.environ, TERM="dumb")
            os.execvpe(command[0], command, environment)
        finally:
            os._exit(127)
    report["controller_child_pid"] = pid
    raw = bytearray()
    ended = False
    code = None

    def event(kind: str, data: bytes = b"", step: int = -1) -> None:
        events.append(
            {
                "event": kind,
                "step": step,
                "elapsed_ns": time.monotonic_ns() - began,
                "hex": data.hex(),
            }
        )

    def poll(timeout: float, step: int) -> bytes:
        nonlocal ended, code
        data = b""
        if select.select([fd], [], [], timeout)[0]:
            try:
                data = os.read(fd, 65536)
            except OSError as exc:
                if exc.errno != 5:
                    raise
            if data:
                raw.extend(data)
                event("output", data, step)
                if len(raw) > 8 * 1024 * 1024:
                    raise ValueError("Terminal output exceeds capture bound")
        child, status = os.waitpid(pid, os.WNOHANG) if not ended else (0, 0)
        if child:
            ended, code = True, os.waitstatus_to_exitcode(status)
            event("process-exit", str(code).encode(), step)
        return data

    try:
        until = time.monotonic() + 1
        while time.monotonic() < until and not ended:
            poll(0.1, -1)
        for index, step in enumerate(plan["steps"]):
            if ended:
                raise RuntimeError(f"Peer exited before step {index}: {code}")
            value = step["command"].encode() + b"\n"
            os.write(fd, value)
            event("input", value, index)
            segment = bytearray()
            deadline = time.monotonic() + step.get("timeout", 15)
            matched = "expect" not in step
            while time.monotonic() < deadline:
                segment.extend(poll(0.1, index))
                clean = re.sub(r"\x1b\[[0-?]*[ -/]*[@-~]", "", segment.decode("latin1"))
                if not matched and re.search(step["expect"], clean, re.DOTALL):
                    matched = True
                    deadline = min(
                        deadline, time.monotonic() + step.get("settle_seconds", 2)
                    )
                if ended:
                    break
                if matched and "expect_exit" in step:
                    continue
                if matched and "expect" not in step:
                    deadline = min(
                        deadline, time.monotonic() + step.get("settle_seconds", 2)
                    )
            if not matched:
                raise TimeoutError(
                    f"Step {index} output did not match {step['expect']!r}"
                )
            if "expect_exit" in step and (not ended or code != step["expect_exit"]):
                raise RuntimeError(f"Step {index} exit differs: {code}")
            report["completed_steps"] += 1
        report["status"] = "completed"
    except (OSError, RuntimeError, ValueError) as exc:
        report["status"], report["error"] = "failed", f"{type(exc).__name__}: {exc}"
    finally:
        if not ended:
            try:
                os.killpg(pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            _, status = os.waitpid(pid, 0)
            code = os.waitstatus_to_exitcode(status)
        os.close(fd)
        report["host_home_file_after"] = home_file_state()
        if report["host_home_file_after"] != original_home_state:
            report["status"], report["error"] = (
                "failed",
                "Host home-file state changed during capture",
            )
        report["peer_exit_code"] = code
        report["finished_at_utc"] = datetime.now(timezone.utc).isoformat()
        (output / "stdout.bin").write_bytes(raw)
        (output / "stdout.txt").write_text(
            raw.decode("utf8", errors="backslashreplace")
        )
        (output / "report.json").write_text(json.dumps(report, indent=2) + "\n")
        (output / "SHA256SUMS").write_text(
            "".join(
                f"{digest(path)}  {path.name}\n"
                for path in sorted(output.iterdir())
                if path.is_file() and path.name != "SHA256SUMS"
            )
        )
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("plan", type=Path)
    parser.add_argument("--binary", type=Path, required=True)
    parser.add_argument("--peer-profile", type=Path, required=True)
    parser.add_argument("--oracle-binary", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    report = capture(
        args.plan, args.binary, args.peer_profile, args.oracle_binary, args.output
    )
    print(
        f"Compiled peer: {report['status']}; {report['completed_steps']} steps; {report['error']}"
    )
    raise SystemExit(report["status"] != "completed")


if __name__ == "__main__":
    main()
