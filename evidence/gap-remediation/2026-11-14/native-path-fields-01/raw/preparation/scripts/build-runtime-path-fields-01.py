#!/usr/bin/env python3
"""Prepared only: pin a live actual emulator after separate START."""

import ast
import datetime as dt
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

R = Path("/data/leynos/Projects/mothra")
O = R / "state/native-sessions/native-path-fields-epoch-01"
DOCS = R.parent / "hotline-protocol-docs"
RUNTIME = R / "state/mac-runtime/native-path-fields-01"
PID = int(sys.argv[1])
assert os.geteuid() == 0 and PID > 0
APPROVED = R / "state/native-sessions/native-path-fields-preparation-01/approved-path-fields-sources.sha256"
APPROVED_HELPERS = R / "state/native-sessions/native-path-fields-preparation-01/approved-helpers.sha256"
APPROVED_CLOSURE = R / "state/native-sessions/native-path-fields-preparation-01/approved-source-closure.sha256"
PROPOSED_CLOSURE = R / "state/native-sessions/native-path-fields-preparation-01/proposed-source-closure.json"
assert APPROVED.is_file(), "Root-approved M1 source pin is absent"
approved_lines = [line.split() for line in APPROVED.read_text().splitlines()]
assert len(approved_lines) == 2 and {line[1] for line in approved_lines} == {
    "scripts/native_path_fields_cases.py", "scripts/native_path_fields_control.py"
}
helper_lines = [line.split() for line in APPROVED_HELPERS.read_text().splitlines()]
assert len(helper_lines) == 3 and {line[1] for line in helper_lines} == {
    "scripts/native_emulator_readiness.py",
    "scripts/native_capture_receipt.py",
    "scripts/capture_readiness.py",
}
closure_lines = [line.split() for line in APPROVED_CLOSURE.read_text().splitlines()]
proposed = json.loads(PROPOSED_CLOSURE.read_text())
closure_hashes = {Path(path).name: digest for digest, path in closure_lines}
assert len(closure_lines) == len(closure_hashes) == len(proposed["hashes"]) and len(closure_hashes) >= 2
assert {path for _, path in closure_lines} == {
    f"scripts/{name}" for name in proposed["hashes"]
}
assert closure_hashes == proposed["hashes"]


def sha(path):
    """Return the SHA-256 hex digest of a file."""
    with path.open("rb") as f:
        return hashlib.file_digest(f, "sha256").hexdigest()


def command(argv):
    """Run a command and return its output, failing on a non-zero exit or a timeout."""
    return subprocess.run(
        argv, capture_output=True, text=True, check=True, timeout=5
    ).stdout


p = Path(f"/proc/{PID}")
raw = (p / "stat").read_text()
start = raw[raw.rfind(")") + 2 :].split()[19]
exe = Path(os.readlink(p / "exe"))
assert sha(exe) == "9c943042993f46cea841812a28975bb4b91de283a37396cddb7604307fb743c4"
image = RUNTIME / "working.dsk"
assert image.stat().st_ino == (p / "fd/6").stat().st_ino == 5999397982
assert os.readlink(p / "fd/6") == str(image)
assert os.readlink(p / "fd/16") == str(O / "lab-guest.pcap")
disk = json.loads((O / "disk-ready.json").read_text())
capture = json.loads((O / "guest-capture-ready.json").read_text())
assert disk["phase"] == "disk" and capture["phase"] == "capture"
for key in ("pid", "start_ticks", "exe_sha256", "uid", "netns_inode", "working_inode"):
    assert disk[key] == capture[key], key
assert disk["pid"] == PID and disk["start_ticks"] == int(start)
assert capture["guest_fd"] == 16
ns = (p / "ns/net").stat().st_ino
assert os.readlink(p / "ns/net") == f"net:[{ns}]"
assert all(
    json.loads(
        command(
            [
                "nsenter",
                "-t",
                str(PID),
                "-n",
                "ip",
                "-j",
                family,
                "route",
                "show",
                "table",
                "main",
            ]
        )
    )
    == []
    for family in ("-4", "-6")
)
assert [
    x["ifname"]
    for x in json.loads(
        command(["nsenter", "-t", str(PID), "-n", "ip", "-j", "link", "show"])
    )
] == ["lo"]
for original, tick in [(1099659, "767842"), (1012834, "2357813")]:
    v = Path(f"/proc/{original}/stat").read_text()
    assert v[v.rfind(")") + 2 :].split()[19] == tick
assert (O / "primary-syn.pcap").stat().st_size == 24
baseline = json.loads(
    (R / "state/native-sessions/native-path-fields-preparation-01/preflight.json").read_text()
)["board"]
assert baseline == {
    "catalog": "11191",
    "data_fork_bytes": 0,
    "resource_fork_bytes": 0,
    "type": "TEXT",
    "creator": "ttxt",
    "istat_sha256": "a920fecd49fdd10ea6b3d01d6786edd743e62a1b7d92d7d96d25952780efbdf2",
}
value = {
    "source_a7_sha256": "5d0aa3dccf65fc6523678aa729c9ace72cd6caffbef768b7f5bf949e6568b43e",
    "fixture_profile": "control-only",
    "full_file_baseline": "not_exercised",
    "emulator_pid": PID,
    "emulator_starttime": start,
    "emulator_sha256": sha(exe),
    "emulator_netns": f"net:[{ns}]",
    "emulator_netns_inode": ns,
    "owned_working_image": str(image),
    "owned_working_image_inode": 5999397982,
    "owned_runtime": str(RUNTIME),
    "source_base_sha256": "e5cbbaaf28481bafbfa6dfe87dd1cac20d71624fe2fbd79c15373a365bde9910",
    "rom_sha256": "18da89e42c7cb68bffe0ec8e404ddd6b2527947d8d5fb6f694a49b2d4a89d2bd",
    "native_data_sha256": "ad7040db4eb67aef1308d915d80305dc96b4aa437a5b3654ea9bb76ab2e4cd1b",
    "stopped_board_baseline": {
        "path": "Hotline19/MessageBoard.txt",
        "catalog_id": 11191,
        "data_size": 0,
        "resource_size": 0,
        "finder_type": "TEXT",
        "finder_creator": "ttxt",
    },
}
assert not (O / "runtime.json").exists()
(O / "runtime.json").write_text(json.dumps(value, indent=2) + "\n")
# Freeze every local Python import reachable from the two M1 modules and
# the readiness/receipt path. Include the explicitly reviewed board collector
# sources even when a current runner keeps its own Wire implementation.
seeds = {
    "native_path_fields_cases", "native_path_fields_control",
    "native_board_cases", "native_board_control",
    "native_ban_control_cases", "native_control_readiness",
    "native_ban_expiry_control", "protocol_capture",
}
pending = sorted(seeds)
resolved = set()
while pending:
    module = pending.pop()
    if module in resolved:
        continue
    path = DOCS / "scripts" / f"{module}.py"
    assert path.is_file(), f"Missing approved local source: {module}"
    resolved.add(module)
    tree = ast.parse(path.read_text(), filename=str(path))
    imports = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imports.update(alias.name.split(".")[0] for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    pending.extend(
        name for name in imports
        if (DOCS / "scripts" / f"{name}.py").is_file() and name not in resolved
    )
assert {f"{module}.py" for module in resolved} == set(closure_hashes)
for name, digest in closure_hashes.items():
    assert len(digest) == 64 and sha(DOCS / "scripts" / name) == digest
folder = O / "sources"
folder.mkdir(exist_ok=False)
hashes = {}
for module in sorted(resolved):
    name = f"{module}.py"
    shutil.copy2(DOCS / "scripts" / name, folder / name)
    hashes[name] = sha(folder / name)
assert hashes == closure_hashes
helper_folder = O / "helper-sources"
helper_folder.mkdir(exist_ok=False)
helper_hashes = {}
for name in ("native_emulator_readiness.py", "native_capture_receipt.py", "capture_readiness.py"):
    shutil.copy2(R / "scripts" / name, helper_folder / name)
    helper_hashes[name] = sha(helper_folder / name)
for digest, path in helper_lines:
    assert len(digest) == 64 and helper_hashes[Path(path).name] == digest
# No source hash is invented here: the root-approved pin must exist and
# match the two approved M1 source files before any native socket.
for digest, path in approved_lines:
    assert len(digest) == 64 and hashes[Path(path).name] == digest
(O / "source-freeze.json").write_text(
    json.dumps(
        {
            "docs_head": command(["git", "-c", f"safe.directory={DOCS}", "-C", str(DOCS), "rev-parse", "HEAD"]).strip(),
            "hashes": hashes,
            "closure_modules": sorted(resolved),
            "helper_hashes": helper_hashes,
        },
        indent=2,
    )
    + "\n"
)
(O / "actual-emulator-proof.json").write_text(
    json.dumps(
        {
            "utc": dt.datetime.now(dt.UTC).isoformat(),
            "pid": PID,
            "starttime": start,
            "exe": str(exe),
            "exe_sha256": sha(exe),
            "fd6": str(image),
            "fd16": str(O / "lab-guest.pcap"),
            "working_image_inode": 5999397982,
            "netns": f"net:[{ns}]",
        },
        indent=2,
    )
    + "\n"
)
print(
    json.dumps(
        {
            "pid": PID,
            "start": start,
            "netns_inode": ns,
            "runtime": str(O / "runtime.json"),
        }
    )
)
