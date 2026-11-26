#!/usr/bin/env python3
"""Run the finite shx receiver matrix with private HOME and loopback capture."""

import argparse
import hashlib
import json
import shutil
import signal
import socket
import subprocess
import sys
import time
from pathlib import Path

from peer_tolerance_fixture import CASES
from protocol_capture import ORACLE_SHA256
from verify_native_shx import PEER


def sha(path: Path) -> str:
    """Return the SHA-256 hex digest of a file's bytes."""
    return hashlib.sha256(path.read_bytes()).hexdigest()


def free(port: int) -> None:
    """Check that a loopback port can be bound."""
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", port))


def run(root: Path, evidence: Path, work: Path, destination: Path) -> None:
    """Run every tolerance case against the peer binary and publish the corpus to the evidence directory."""
    root, evidence, work, destination = (
        path.resolve() for path in (root, evidence, work, destination)
    )
    private_root = root / "state/delegation/peer"
    owned_evidence = root / "evidence/gap-remediation/2026-11-13/delegated-peer-01"
    if not work.is_relative_to(private_root) or destination != owned_evidence:
        raise ValueError("Output paths must be owned private or evidence paths")
    if work.exists() or destination.exists():
        raise ValueError("Run and evidence outputs must be fresh")
    binary = root / "tools/shx-peer/source/hx"
    oracle = root / "evidence/hotline-server-1.9/inputs/HLserver19.pef"
    profile = (
        root / "evidence/gap-remediation/2026-11-13/native-shx-02/peer-profile.json"
    )
    if sha(binary) != PEER or sha(oracle) != ORACLE_SHA256:
        raise ValueError("Peer/oracle identity mismatch")
    if json.loads(profile.read_text())["binary_sha256"] != PEER:
        raise ValueError("Recorded profile does not match the running peer")
    for port in range(15600, 15600 + len(CASES)):
        free(port)
    work.mkdir(parents=True)
    (work / "captures").mkdir()
    (work / "fixtures").mkdir()
    plan_source = (
        root
        / "evidence/gap-remediation/2026-11-13/native-shx-02/receivers/control/plan.json"
    )
    plan_template = json.loads(plan_source.read_text())
    own_home = Path.home() / ".hxvars"
    before = (
        (sha(own_home), own_home.stat().st_size, own_home.stat().st_mtime_ns)
        if own_home.exists()
        else None
    )
    capture = subprocess.Popen(
        [
            "sudo",
            "-n",
            "tcpdump",
            "-i",
            "lo",
            "-y",
            "EN10MB",
            "-s",
            "0",
            "-U",
            "-Z",
            "leynos",
            "-w",
            str(work / "host.pcap"),
            "tcp",
            "and",
            "portrange",
            "15600-15609",
        ],
        stdout=(work / "tcpdump.stdout").open("w"),
        stderr=(work / "tcpdump.stderr").open("w"),
    )
    try:
        time.sleep(1)
        if capture.poll() is not None:
            raise RuntimeError("Loopback recorder exited before first session")
        for index, case in enumerate(CASES):
            port = 15600 + index
            fixture = work / "fixtures" / case
            plan = json.loads(json.dumps(plan_template))
            plan["environment"] = {
                "controlled_receiver_fixture": {
                    "profile": "controlled-receiver-fixture",
                    "case": case,
                    "source_peer": "shx 0.1.48 modern terminal build",
                }
            }
            plan["steps"][1]["command"] = plan["steps"][1]["command"].replace(
                ":15510", f":{port}"
            )
            case_plan = work / f"plan-{case}.json"
            case_plan.write_text(json.dumps(plan, indent=2) + "\n")
            with (work / f"fixture-{case}.log").open("w") as log:
                server = subprocess.Popen(
                    [
                        sys.executable,
                        str(evidence / "scripts/peer_tolerance_fixture.py"),
                        "--evidence",
                        str(root / "evidence/gap-remediation/2026-11-13"),
                        "--case",
                        case,
                        "--port",
                        str(port),
                        "--output",
                        str(fixture),
                    ],
                    stdout=log,
                    stderr=subprocess.STDOUT,
                )
                deadline = time.monotonic() + 10
                while not (fixture / "ready.json").exists():
                    if server.poll() is not None or time.monotonic() > deadline:
                        raise RuntimeError(f"Fixture did not start: {case}")
                    time.sleep(0.1)
                result = subprocess.run(
                    [
                        sys.executable,
                        str(evidence / "scripts/capture_shx_session.py"),
                        str(case_plan),
                        "--binary",
                        str(binary),
                        "--peer-profile",
                        str(profile),
                        "--oracle-binary",
                        str(oracle),
                        "--output",
                        str(work / "captures" / case),
                    ],
                    capture_output=True,
                    text=True,
                    check=False,
                )
                (work / f"capture-{case}.log").write_text(result.stdout + result.stderr)
                try:
                    server_code = server.wait(timeout=35)
                except subprocess.TimeoutExpired:
                    server.send_signal(signal.SIGTERM)
                    server.wait(timeout=5)
                    raise RuntimeError(f"Fixture remained live: {case}") from None
                if result.returncode or server_code:
                    raise RuntimeError(f"Session failed: {case}; preserved at {work}")
            print(f"Completed full peer session: {case}", flush=True)
    finally:
        capture.send_signal(signal.SIGINT)
        capture.wait(timeout=10)
    after = (
        (sha(own_home), own_home.stat().st_size, own_home.stat().st_mtime_ns)
        if own_home.exists()
        else None
    )
    if after != before:
        raise RuntimeError(
            "Real HOME/.hxvars changed; preserve private run and escalate"
        )
    (work / "sources").mkdir()
    for name in (
        "peer_tolerance_fixture.py",
        "peer_tolerance_run.py",
        "verify_peer_tolerance.py",
        "capture_shx_session.py",
    ):
        shutil.copy2(evidence / "scripts" / name, work / "sources" / name)
    (work / "manifest.json").write_text(
        json.dumps(
            {
                "schema_version": 1,
                "profile": "compiled-historical-peer and controlled-receiver-fixture",
                "native_conformance": False,
                "source_commit": json.loads(profile.read_text())["source_commit"],
                "peer_binary_sha256": PEER,
                "oracle_sha256": ORACLE_SHA256,
                "cases": list(CASES),
                "ports": list(range(15600, 15600 + len(CASES))),
                "real_home_file_before": before,
                "real_home_file_after": after,
                "source_fixture_sha256": sha(
                    evidence / "scripts/peer_tolerance_fixture.py"
                ),
                "source_runner_sha256": sha(Path(__file__)),
            },
            indent=2,
        )
        + "\n"
    )
    (work / "SHA256SUMS").write_text(
        "".join(
            f"{sha(path)}  {owned_evidence.relative_to(root) / path.relative_to(work)}\n"
            for path in sorted(work.rglob("*"))
            if path.is_file() and path.name != "SHA256SUMS"
        )
    )
    destination.parent.mkdir(parents=True, exist_ok=True)
    shutil.copytree(work, destination)
    print(f"Frozen evidence: {destination}")


def main() -> None:
    """Parse the command line and run the tolerance cases."""
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--protocol", type=Path, required=True)
    parser.add_argument("--work", type=Path, required=True)
    parser.add_argument("--destination", type=Path, required=True)
    args = parser.parse_args()
    run(args.root, args.protocol, args.work, args.destination)


if __name__ == "__main__":
    main()
