"""Read-only candidate import inventory; root must later pin canonical bytes."""

import ast
import hashlib
import json
from pathlib import Path

ROOT = Path("/data/leynos/Projects/mothra")
OUT = ROOT / "state/native-sessions/native-alias-live-preparation-03"
CANON = ROOT.parent / "hotline-protocol-docs/scripts"
OWNED = {"native_missing_alias_cases", "native_missing_alias_control"}
SEEDS = OWNED | {
    "native_ban_control_cases",
    "native_control_readiness",
    "native_ban_expiry_control",
    "protocol_capture",
}


def source(name: str) -> Path:
    """Return the path of a named source file in the canonical tree."""
    return CANON / f"{name}.py"


pending = sorted(SEEDS)
resolved = {}
while pending:
    name = pending.pop()
    if name in resolved:
        continue
    path = source(name)
    if not path.is_file():
        raise FileNotFoundError(path)
    raw = path.read_bytes()
    resolved[name] = {"origin": str(path), "sha256": hashlib.sha256(raw).hexdigest()}
    imports = set()
    for node in ast.walk(ast.parse(raw, filename=str(path))):
        if isinstance(node, ast.Import):
            imports.update(a.name.split(".")[0] for a in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imports.add(node.module.split(".")[0])
    pending.extend(n for n in imports if n not in resolved and source(n).is_file())
helpers = {}
for name in (
    "native_emulator_readiness.py",
    "capture_readiness.py",
    "native_capture_receipt.py",
):
    path = ROOT / "scripts" / name
    helpers[name] = hashlib.sha256(path.read_bytes()).hexdigest()
record = {
    "status": "canonical_candidate_not_root_approved_no_snapshot",
    "protocol_modules": {k: resolved[k] for k in sorted(resolved)},
    "helpers": helpers,
    "count": len(resolved),
    "root_pin_files_absent": [
        "approved-alias-live-sources.sha256",
        "approved-source-closure.sha256",
        "approved-helpers.sha256",
        "script-SHA256SUMS",
        "proposed-source-closure.json",
    ],
}
path = OUT / "candidate-source-closure.json"
if path.exists():
    raise FileExistsError(path)
path.write_text(json.dumps(record, indent=2) + "\n")
print(
    len(resolved),
    resolved["native_missing_alias_cases"]["sha256"],
    resolved["native_missing_alias_control"]["sha256"],
)
